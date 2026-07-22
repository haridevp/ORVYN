import subprocess
import json
import os
import sys
import argparse
import time
from typing import List, Dict, Any

def normalize_findings(raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Strips raw Nuclei output to retain only essential fields.
    This reduces token consumption when feeding results into Qwen 2.5 / Ollama.
    """
    clean_findings = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue

        info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
        
        clean_findings.append({
            "template_id": item.get("template-id", "unknown"),
            "name": info.get("name", "Unnamed Finding"),
            "severity": info.get("severity", "unknown"),
            "matched_at": item.get("matched-at", item.get("host", "N/A")),
            "description": info.get("description", "No detailed description provided."),
            "extracted_data": item.get("extracted-results", []),
            "curl_command": item.get("curl-command", "")
        })
    return clean_findings


def run_nuclei_scan(target_url: str, severity: List[str] = None, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Executes a fast, targeted Nuclei scan on lightweight templates without buffer locks.
    """
    if severity is None:
        severity = ["info", "low", "medium", "high", "critical"]
    
    severity_str = ",".join(severity)
    output_file = "/tmp/temp_scan_results.json"
    
    if os.path.exists(output_file):
        os.remove(output_file)
    
    # Full default scan across all protocol categories (HTTP, SSH, DNS, SSL, etc.)
    command = [
        "nuclei",
        "-u", target_url,
        "-severity", severity_str,
        "-json-export", output_file,
        "-rate-limit", "150",       # Max 150 requests/sec for speed
        "-concurrency", "25",       # 25 templates in parallel
        "-timeout", "5",            # Drop individual hanging requests after 5s
        "-silent"
    ]
    
    try:
        print(f"[*] Triggering fast Nuclei scan for target: {target_url}...")
        
        # FIX: Discard stdout/stderr directly to prevent subprocess buffer deadlocks
        with open(os.devnull, 'w') as devnull:
            proc = subprocess.Popen(command, stdout=devnull, stderr=devnull)
            
            start_time = time.time()
            while proc.poll() is None:
                if time.time() - start_time > timeout:
                    proc.kill()
                    print(f"[!] Scan process forcefully killed after {timeout} seconds timeout.")
                    return []
                time.sleep(1)
        
        raw_results = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str:
                        try:
                            parsed = json.loads(line_str)
                            if isinstance(parsed, list):
                                raw_results.extend(parsed)
                            elif isinstance(parsed, dict):
                                raw_results.append(parsed)
                        except json.JSONDecodeError:
                            continue
            
            os.remove(output_file)
            
        print(f"[+] Scan completed successfully. Found {len(raw_results)} raw items.")
        return normalize_findings(raw_results)

    except KeyboardInterrupt:
        print("\n[!] Scan manually interrupted by user (Ctrl+C). Cleaning up...")
        if os.path.exists(output_file):
            os.remove(output_file)
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected error during scan: {str(e)}")
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nuclei scan on a target URL and export clean JSON.")
    parser.add_argument("url", nargs="?", help="Target URL or IP (e.g., http://scanme.sh)")
    
    args = parser.parse_args()
    
    target_url = args.url
    if not target_url:
        target_url = input("Enter target URL or IP address (e.g. http://scanme.sh): ").strip()
    
    if not target_url:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    findings = run_nuclei_scan(target_url)
    
    output_path = "sample_scan_for_ai.json"
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)
        
    print(f"[+] Saved {len(findings)} clean findings to '{output_path}'.")
