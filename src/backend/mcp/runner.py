"""HexStrike Curated MCP Runner.

Executes security tools either via:
1. Native host execution (when running on Kali Linux or Parrot OS)
2. Isolated Docker container invocation (when running on other Linux distros)
3. Simulated fallback execution (when offline / local dev)
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

        # Mode A: Native execution (Kali, Parrot, or host binary available)
        if tool in self.env.available_tools:
            cmd = [tool] + args
            if log_cb:
                log_cb(f"[HexStrike-Native] Executing on host: {' '.join(cmd)}")
            return await self._run_subprocess(tool, cmd, timeout, log_cb, mode=self.env.execution_mode.value)

        # Mode B: Dockerized tool execution
        if self.env.docker_available:
            docker_cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "host",
                self.docker_image,
                tool,
            ] + args
            if log_cb:
                log_cb(f"[HexStrike-Docker] Executing in container: {' '.join(docker_cmd)}")
            return await self._run_subprocess(tool, docker_cmd, timeout, log_cb, mode="dockerized_mcp")

        # Mode C: Fallback simulated tool execution
        if log_cb:
            log_cb(f"[HexStrike-Simulated] Tool '{tool}' not installed on host and Docker daemon unavailable. Running simulated engine.")
        return ToolExecutionResult(
            tool=tool,
            command=[tool] + args,
            returncode=0,
            stdout=f"[Simulated {tool} output for {' '.join(args)}]",
            stderr="",
            execution_mode=ExecutionMode.SIMULATED.value,
            is_success=True,
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
