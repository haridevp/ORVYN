"""HexStrike Curated MCP Runner.

Executes security tools either via:
1. Native host execution (when running on Kali Linux or Parrot OS or Linux host)
2. Isolated Docker container invocation (when running on other Linux distros)
"""

import asyncio
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable, Optional

from environment import ExecutionMode, detect_environment

logger = logging.getLogger("hexstrike.mcp.runner")


@dataclass
class ToolExecutionResult:
    tool: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    execution_mode: str
    is_success: bool


class HexStrikeRunner:
    def __init__(self) -> None:
        self.env = detect_environment()
        self.docker_image = os.environ.get("HEXSTRIKE_DOCKER_IMAGE", "pentest-backend:latest")

    def refresh_environment(self) -> None:
        self.env = detect_environment()

    async def run_tool(
        self,
        tool: str,
        args: list[str],
        timeout: int = 120,
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> ToolExecutionResult:
        """Run a security tool respecting Kali/Parrot native execution or Docker containerization."""
        self.refresh_environment()

        from environment import get_container_cli

        # Mode A: Native execution - strictly permitted ONLY on Kali Linux, Parrot OS, or inside a container
        is_kali_or_parrot = self.env.execution_mode in (ExecutionMode.NATIVE_KALI, ExecutionMode.NATIVE_PARROT)
        if (is_kali_or_parrot or self.env.is_docker) and tool in self.env.available_tools:
            cmd = [tool] + args
            if log_cb:
                log_cb(f"[HexStrike-Native] Executing on host: {' '.join(cmd)}")
            return await self._run_subprocess(tool, cmd, timeout, log_cb, mode=self.env.execution_mode.value)

        # Mode B: Containerized tool execution (Strict isolation on all other OSes)
        container_cli = get_container_cli() or "docker"
        if self.env.docker_available or shutil.which(container_cli):
            container_cmd = [
                container_cli,
                "run",
                "--rm",
                "--network",
                "host",
                self.docker_image,
                tool,
            ] + args
            if log_cb:
                log_cb(f"[HexStrike-{container_cli.capitalize()}] Executing in container: {' '.join(container_cmd)}")
            return await self._run_subprocess(tool, container_cmd, timeout, log_cb, mode="dockerized_mcp")

        # Container engine unavailable on non-Kali/non-Parrot host
        err_msg = (
            f"Tool '{tool}' requires {container_cli.capitalize()} container execution on {self.env.os_name}. "
            "Native host execution is restricted strictly to Kali Linux or Parrot OS."
        )
        if log_cb:
            log_cb(f"[HexStrike-Error] {err_msg}")
        return ToolExecutionResult(
            tool=tool,
            command=[tool] + args,
            returncode=127,
            stdout="",
            stderr=err_msg,
            execution_mode=self.env.execution_mode.value,
            is_success=False,
        )

    async def _run_subprocess(
        self,
        tool: str,
        cmd: list[str],
        timeout: int,
        log_cb: Optional[Callable[[str], None]] = None,
        mode: str = "native",
    ) -> ToolExecutionResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_data, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            stdout_str = stdout_data.decode("utf-8", errors="replace")
            stderr_str = stderr_data.decode("utf-8", errors="replace")

            if log_cb and stdout_str:
                for line in stdout_str.splitlines()[:10]:
                    log_cb(f"[{tool}] {line}")

            return ToolExecutionResult(
                tool=tool,
                command=cmd,
                returncode=proc.returncode or 0,
                stdout=stdout_str,
                stderr=stderr_str,
                execution_mode=mode,
                is_success=proc.returncode == 0,
            )
        except asyncio.TimeoutError:
            if log_cb:
                log_cb(f"[{tool}] Timed out after {timeout} seconds.")
            return ToolExecutionResult(
                tool=tool,
                command=cmd,
                returncode=-1,
                stdout="",
                stderr=f"Execution timed out after {timeout}s",
                execution_mode=mode,
                is_success=False,
            )
        except Exception as exc:
            if log_cb:
                log_cb(f"[{tool}] Execution error: {exc}")
            return ToolExecutionResult(
                tool=tool,
                command=cmd,
                returncode=-1,
                stdout="",
                stderr=str(exc),
                execution_mode=mode,
                is_success=False,
            )


hexstrike_runner = HexStrikeRunner()
