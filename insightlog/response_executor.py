"""
InsightLog - Human-in-the-Loop Response Executor
Executes approved remediation commands and logs to D3
"""
import subprocess
import shlex
import os
import pwd

from insightlog import db_manager as db


def _get_protected_users() -> set:
    """Users that must never be targeted by destructive commands."""
    protected = {"root"}
    try:
        protected.add(os.environ.get("SUDO_USER", ""))
        protected.add(pwd.getpwuid(os.getuid()).pw_name)
        protected.add(pwd.getpwuid(os.geteuid()).pw_name)
    except Exception:
        pass
    try:
        import grp
        for grp_name in ("sudo", "wheel", "admin"):
            try:
                protected.update(grp.getgrnam(grp_name).gr_mem)
            except KeyError:
                pass
    except Exception:
        pass
    return {u for u in protected if u}


# Commands that modify or delete a user — require extra safety check
_DESTRUCTIVE_USER_CMDS = {"passwd", "userdel", "usermod", "chpasswd"}

SAFE_COMMANDS = [
    "iptables", "ufw", "passwd", "userdel", "usermod",
    "systemctl", "pkill", "kill", "ss", "netstat",
    "who", "last", "journalctl", "smartctl", "fsck",
    "free", "vmstat", "fail2ban-client", "sshd",
]


def is_safe(cmd: str) -> bool:
    parts = shlex.split(cmd)
    if not parts:
        return False
    return os.path.basename(parts[0]) in SAFE_COMMANDS


def execute_action(incident_id: int, command: str,
                   approved_by: str = "operator") -> dict:
    result_text = ""
    success = 0

    if not command.strip():
        return {"success": False, "result": "Empty command."}

    if not is_safe(command):
        result_text = f"BLOCKED: '{command}' is not in the safe command list."
        db.insert_audit({
            "incident_id": incident_id,
            "action_type": "blocked",
            "command":     command,
            "result":      result_text,
            "approved_by": approved_by,
            "success":     0,
        })
        return {"success": False, "result": result_text}

    # Safety: block destructive commands targeting protected users
    try:
        parts = shlex.split(command)
        cmd_name = os.path.basename(parts[0]) if parts else ""
        if cmd_name in _DESTRUCTIVE_USER_CMDS:
            # Find the target username — last non-flag argument
            target = next(
                (p for p in reversed(parts[1:]) if not p.startswith("-")),
                None
            )
            if target and target in _get_protected_users():
                result_text = (
                    f"BLOCKED: '{command}' targets protected account '{target}'. "
                    f"This account belongs to the system operator or a sudo group member "
                    f"and cannot be modified automatically."
                )
                db.insert_audit({
                    "incident_id": incident_id,
                    "action_type": "blocked_safety",
                    "command":     command,
                    "result":      result_text,
                    "approved_by": approved_by,
                    "success":     0,
                })
                return {"success": False, "result": result_text}
    except Exception:
        pass

    try:
        proc = subprocess.run(
            shlex.split(command),
            capture_output=True, text=True, timeout=30
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
    print(f"\n[Executor] Suggested actions for Incident #{incident_id}:")
    for i, s in enumerate(suggestions, 1):
        print(f"  {i}. {s}")
    print(f"  {len(suggestions)+1}. Enter custom command")
    print(f"  0. Skip\n")

    while True:
        choice = input("Select action number (0 to exit): ").strip()

        if choice == "0":
            print("[Executor] No action taken.")
            return

        if choice.isdigit() and 1 <= int(choice) <= len(suggestions):
            cmd = suggestions[int(choice) - 1]
            if ":" in cmd:
                cmd = cmd.split(":", 1)[1].strip()
        elif choice == str(len(suggestions) + 1):
            cmd = input("Enter command: ").strip()
        else:
            print("  Invalid choice.")
            continue

        print(f"\n  Command : {cmd}")
        confirm = input("  Approve and execute? [y/N]: ").strip().lower()
        if confirm == "y":
            print("  Executing...")
            result = execute_action(incident_id, cmd)
            status = "Success" if result["success"] else "Failed"
            print(f"  {status}: {result['result']}")
            again = input("\n  Execute another action? [y/N]: ").strip().lower()
            if again != "y":
                return
        else:
            print("  Action cancelled.")