"""
Human-in-the-Loop Response Executor
Executes approved actions and logs everything to D3
"""
import subprocess
import shlex
import os
from datetime import datetime
import db_manager as db

SAFE_COMMANDS = [
    "iptables",
    "ufw",
    "passwd",
    "userdel",
    "usermod",
    "systemctl",
    "pkill",
    "kill",
    "sshd",
    "ss",
    "netstat",
    "who",
    "last",
    "journalctl",
    "smartctl",
    "fsck",
    "free",
    "vmstat",
    "fail2ban-client",
]


def is_safe(cmd: str) -> bool:
    """Check if command starts with a safe allowed binary."""
    parts = shlex.split(cmd)
    if not parts:
        return False
    binary = os.path.basename(parts[0])
    return binary in SAFE_COMMANDS


def execute_action(incident_id: int, command: str, approved_by: str = "operator") -> dict:
    """
    Execute a remediation command after human approval.
    Logs to D3 regardless of success/failure.
    """
    result_text = ""
    success = 0

    if not command.strip():
        return {"success": False, "result": "Empty command."}

    if not is_safe(command):
        result_text = f"BLOCKED: Command '{command}' is not in the safe list."
        db.insert_audit({
            "incident_id": incident_id,
            "action_type": "blocked_execution",
            "command":     command,
            "result":      result_text,
            "approved_by": approved_by,
            "success":     0,
        })
        return {"success": False, "result": result_text}

    try:
        proc = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=30
        )
        result_text = (proc.stdout + proc.stderr).strip()
        success = 1 if proc.returncode == 0 else 0
    except subprocess.TimeoutExpired:
        result_text = "Command timed out after 30s."
    except Exception as e:
        result_text = f"Execution error: {e}"

    db.insert_audit({
        "incident_id": incident_id,
        "action_type": "execute",
        "command":     command,
        "result":      result_text[:2000],
        "approved_by": approved_by,
        "success":     success,
    })

    return {"success": bool(success), "result": result_text}


def interactive_execute(incident_id: int, suggestions: list) -> None:
    """Interactive human-in-the-loop approval and execution loop."""
    print(f"\n[Executor] Suggested actions for Incident #{incident_id}:")
    for i, s in enumerate(suggestions, 1):
        print(f"  {i}. {s}")
    print(f"  {len(suggestions)+1}. Enter custom command")
    print(f"  0. Skip / Do nothing\n")

    while True:
        choice = input("Select action number (or 0 to exit): ").strip()
        if choice == "0":
            print("[Executor] No action taken.")
            return

        if choice.isdigit() and 1 <= int(choice) <= len(suggestions):
            cmd = suggestions[int(choice) - 1]
            # Extract command from suggestion text
            if ":" in cmd:
                cmd = cmd.split(":", 1)[1].strip()
        elif choice == str(len(suggestions) + 1):
            cmd = input("Enter command: ").strip()
        else:
            print("Invalid choice.")
            continue

        print(f"\n  Command  : {cmd}")
        confirm = input("  Approve and execute? [y/N]: ").strip().lower()
        if confirm == "y":
            print("[Executor] Executing...")
            result = execute_action(incident_id, cmd)
            status = "✓ Success" if result["success"] else "✗ Failed"
            print(f"  {status}: {result['result']}")
            another = input("\nExecute another action? [y/N]: ").strip().lower()
            if another != "y":
                return
        else:
            print("[Executor] Action cancelled.")