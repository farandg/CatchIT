import os
import argparse
import json
import logging
import math
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from config import Catchit_Config
from output import CatchIT_Ouput

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

BASE_PATH = Path(__file__).parent
TS_START = time.time()
FILE_REGEXS = BASE_PATH / "regexs.json"
EXEC_GREP_SCRIPT = BASE_PATH / "grep_tunnel.sh"
EXEC_FIND_SCRIPT = BASE_PATH / "find_tunnel.sh"
INVERSE_GREP = BASE_PATH / "inverse_grep.txt"
BASE64_CHARS = "+/=" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

catchit_output = CatchIT_Ouput()
catchit_config = Catchit_Config()

def check_operating_system():
    """Configure tunnel flags and bash path based on the detected operating system."""
    if sys.platform == "win32":
        catchit_config.bash = "C:\\Program Files\\Git\\bin\\bash.exe"
        catchit_config.system_path_sep = "**\\*"
        catchit_config.tunnel_flags = "-E"
    elif sys.platform == "darwin":
        catchit_config.tunnel_flags = "-E"
    elif sys.platform.startswith("linux"):
        catchit_config.tunnel_flags = "-P"

def getFinding_GREP(
    proc: subprocess.CompletedProcess,
    scanning_path: str,
    confidence: float = 0.4,
    entropy: float = 0,
) -> List[Dict]:
    """Parse findings from GREP subprocess output."""
    # logger.info("Starting getFinding_grep")
    findings = []
    try:
        proc_output = proc.stdout.decode("utf-8").split("\n")
        for line in proc_output:
            finding = {}
            out_line = line.split(":")
            if len(out_line) < 2:
                continue

            path = str(Path(out_line[0]).relative_to(scanning_path))
            if sys.platform == "win32" and ":" in out_line[0]:
                path = str(Path(out_line[0] + ":" + out_line[1]).relative_to(scanning_path))
            
            finding["path"] = path
            finding["line"] = out_line[1]
            finding["match"] = ":".join(out_line[2:])
            catchit_output.summary["findings"]["code"] += 1

            if confidence >= 0.5 and shannon_entropy(out_line[2], BASE64_CHARS) > entropy:
                catchit_output.summary["findings"]["blocking_code"] += 1
                finding["type"] = "Blocking"
            else:
                finding["type"] = "Non-Blocking"

            findings.append(finding)

        return findings
    except Exception as e:
        logger.error("Error in getFinding_grep:", exc_info=True)
        return []

def getFinding_FIND(
    proc: subprocess.CompletedProcess, scanning_path: str, confidence: float = 0.4
) -> List[Dict]:
    """Parse findings from FIND subprocess output."""
    # logger.info("Starting getFinding_find")
    findings = []
    try:
        proc_output = proc.stdout.decode("utf-8").split("\n")
        for line in proc_output:
            finding = {}
            out_line = line.split(":")
            if not out_line[0]:
                continue

            path = str(Path(out_line[0]).relative_to(scanning_path))
            finding["path"] = path
            catchit_output.summary["findings"]["file"] += 1

            if confidence >= 0.5:
                catchit_output.summary["findings"]["blocking_file"] += 1
                finding["type"] = "Blocking"
            else:
                finding["type"] = "Non-Blocking"

            findings.append(finding)

        return findings
    except Exception as e:
        logger.error("Error in getFinding_find:", exc_info=True)
        return []

def exec_grep(regexs_json: Dict, scanning_path: str, tunnel_flags: str) -> List[Dict]:
    """Execute GREP-based scanning for suspicious code."""
    # logger.info("Starting exec_grep")
    findings = []
    try:
        for regex_key, regex_value in regexs_json.get("CODE_SCANNING", {}).items():
            regex = regex_value.get("regex")
            if not regex:
                logger.error(f"Regex missing for {regex_key}")
                continue

            confidence = regex_value.get("confidence", 0)
            entropy = regex_value.get("entropy", 0)

            try:
                if confidence > 0:
                    proc = subprocess.run(
                        [
                            catchit_config.bash,
                            str(EXEC_GREP_SCRIPT),
                            regex,
                            scanning_path,
                            str(INVERSE_GREP),
                            tunnel_flags,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,  # Increased timeout for longer scans
                    )
                    findings.append({
                        "findings": getFinding_GREP(proc, scanning_path, confidence, entropy),
                        "regex_key": regex_key,
                        "regex_value": regex
                    })
            except subprocess.TimeoutExpired:
                logger.error("exec_grep timed out")

    except Exception as e:
        logger.error("Error in exec_grep:", exc_info=True)

    # logger.info("exec_grep successfully completed")
    return findings

def exec_find(regexs_json: Dict, scanning_path: str, tunnel_flags: str):
    """Execute FIND-based scanning for suspicious files."""
    # logger.info("Starting exec_find")
    findings = []
    try:
        for file_key, file_value in regexs_json.get("FILE_SCANNING", {}).items():
            regex = file_value.get("regex")
            if not regex:
                logger.error(f"Regex missing for {file_key}")
                continue

            confidence = file_value.get("confidence", 0)

            try:
                if confidence > 0:
                    proc = subprocess.run(
                        [
                            catchit_config.bash,
                            str(EXEC_FIND_SCRIPT),
                            scanning_path,
                            regex,
                            tunnel_flags,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,  # Increased timeout for longer scans
                    )
                    findings.append({
                        "findings": getFinding_FIND(proc, scanning_path, confidence),
                        "file_key": file_key,
                        "file_value": regex
                    })
            except subprocess.TimeoutExpired:
                logger.error("exec_find timed out")
    except Exception as e:
        logger.error("Error in exec_find:", exc_info=True)

    # logger.info("exec_find completed successfully")
    return findings

def shannon_entropy(data: str, iterator: str) -> float:
    """Calculate Shannon entropy of a string based on provided characters."""
    try:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log(count / length, 2) for count in counts.values())
    except Exception as e:
        logger.error("Error in calculating Shannon entropy:", exc_info=True)
        return 0.0

def main():
    # logger.info("####   STARTING CATCHIT   ####")

    parser = argparse.ArgumentParser(description="CatchIt plugins")
    parser.add_argument(
        "--bash-path",
        help="Path to the bash supported terminal, defaults to bash",
        default=catchit_config.bash,
    )
    parser.add_argument("--scan-path", help="Path for scan", default=os.getcwd())

    args = parser.parse_args()
    catchit_config.scanning_path = str(args.scan_path)
    catchit_config.bash = str(args.bash_path)

    with open(FILE_REGEXS, "r") as f:
        regexs_json = json.load(f)

    check_operating_system()

    # Execute GREP scanning
    time_grep = time.time()
    catchit_output.code = exec_grep(
        regexs_json, catchit_config.scanning_path, catchit_config.tunnel_flags
    )
    catchit_output.summary["execution_time"]["code"] = time.time() - time_grep

    # Execute FIND scanning
    time_find = time.time()
    catchit_output.file = exec_find(
        regexs_json, catchit_config.scanning_path, catchit_config.tunnel_flags
    )
    catchit_output.summary["execution_time"]["file"] = time.time() - time_find

    total_block_findings = (
        catchit_output.summary["findings"]["blocking_code"]
        + catchit_output.summary["findings"]["blocking_file"]
    )
    catchit_output.summary["execution_time"]["total"] = time.time() - TS_START

    print(json.dumps(catchit_output.__dict__, indent=4))

    if total_block_findings > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
