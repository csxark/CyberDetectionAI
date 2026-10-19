"""Local curated knowledge base data for ATT&CK techniques, CWEs, and Sigma detection rules."""
from __future__ import annotations

from typing import Any

ATTACK_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "mitigation": "Multi-factor authentication, account auditing, credential rotation.",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.",
        "mitigation": "Account lockout thresholds, rate limiting, IP reputation filtering.",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "mitigation": "Script block logging, restricted language modes, execution policy.",
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
        "mitigation": "Input sanitization, web application firewall, regular patching.",
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as SSH, RDP, or SMB.",
        "mitigation": "Network segmentation, jump hosts, disable unused remote administration services.",
    },
    "T1070": {
        "id": "T1070",
        "name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or alter generated artifacts on a host system, including logs / audit trails.",
        "mitigation": "Centralized, append-only, write-once log forwarding.",
    },
}

CWES: dict[str, dict[str, Any]] = {
    "CWE-307": {
        "id": "CWE-307",
        "name": "Improper Restriction of Excessive Authentication Attempts",
        "description": "The software does not properly restrict the number of consecutive failed authentication attempts.",
    },
    "CWE-89": {
        "id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component.",
    },
    "CWE-22": {
        "id": "CWE-22",
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "The software uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize sequences such as '..' that can resolve to a location that is outside that directory.",
    },
}

SIGMA_RULES: list[dict[str, Any]] = [
    {
        "id": "SIGMA-001",
        "title": "Multiple Failed Authentication Attempts (Brute Force)",
        "level": "high",
        "technique": "T1110",
        "cwe": "CWE-307",
        "keywords": ["failed password", "login failed", "authentication failure", "invalid credentials", "401 unauthorized"],
        "min_matches": 3,
    },
    {
        "id": "SIGMA-002",
        "title": "Path Traversal in Web Requests",
        "level": "high",
        "technique": "T1190",
        "cwe": "CWE-22",
        "keywords": ["../", "..\\", "%2e%2e", "/etc/passwd", "win.ini"],
        "min_matches": 1,
    },
    {
        "id": "SIGMA-003",
        "title": "SQL Injection Pattern Detected",
        "level": "critical",
        "technique": "T1190",
        "cwe": "CWE-89",
        "keywords": ["union select", "' or 1=1", "information_schema", "-- -", "; drop table"],
        "min_matches": 1,
    },
    {
        "id": "SIGMA-004",
        "title": "Suspicious Privilege Escalation / Sudo Execution",
        "level": "high",
        "technique": "T1078",
        "cwe": "CWE-287",
        "keywords": ["sudo: ", "su: root", "privilege escalation", "pwned", "administrator session started"],
        "min_matches": 1,
    },
]
