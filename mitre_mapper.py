# MITRE ATT&CK Rule-Based Mapper
# No API key needed — always works

MITRE_RULES = [
    # Brute Force / Auth
    (["failed login", "authentication failure", "invalid user", "wrong password", "brute"], "T1110", "Brute Force", "Credential Access"),
    # Rootkit
    (["rootkit", "hidden process", "kernel module"], "T1014", "Rootkit", "Defense Evasion"),
    # File Integrity
    (["file modified", "file added", "file deleted", "integrity", "syscheck"], "T1565", "Data Manipulation", "Impact"),
    # Process
    (["new process", "process created", "cmd.exe", "powershell", "command execution"], "T1059", "Command and Scripting Interpreter", "Execution"),
    # Network
    (["port scan", "network connection", "suspicious connection"], "T1046", "Network Service Discovery", "Discovery"),
    # Privilege
    (["privilege escalation", "sudo", "administrator", "elevated"], "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    # Malware
    (["malware", "virus", "trojan", "suspicious file", "malicious"], "T1204", "User Execution", "Execution"),
    # Registry
    (["registry", "regedit", "hkey"], "T1112", "Modify Registry", "Defense Evasion"),
    # Account
    (["new user", "user created", "account created"], "T1136", "Create Account", "Persistence"),
    # Firewall
    (["firewall", "rule added", "blocked"], "T1562", "Impair Defenses", "Defense Evasion"),
]

def get_mitre_tag(description):
    desc_lower = description.lower()
    for keywords, tid, tname, tactic in MITRE_RULES:
        for kw in keywords:
            if kw in desc_lower:
                return tid, tname, tactic
    return "T0000", "Unknown Technique", "Unknown"
