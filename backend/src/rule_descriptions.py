"""Rule descriptions and severity levels for security evaluations."""

RULE_DESCRIPTIONS = {
    "patch_status": {
        "description": "System patches are not up-to-date.",
        "level": "critical",
    },
    "open_ports": {
        "description": "Open TCP ports found.",
        "level": "warning",
    },
    "service_count": {
        "description": "Number of running services exceeds threshold",
        "level": "info",
    },
    "firewall_all_disabled": {
        "description": "All firewall profiles are disabled.",
        "level": "critical",
    },
    "firewall_public_disabled": {
        "description": "Public firewall profile is disabled.",
        "level": "warning",
    },
    "firewall_domain_disabled": {
        "description": "Domain firewall profile is disabled.",
        "level": "warning",
    },
    "firewall_private_disabled": {
        "description": "Private firewall profile is disabled.",
        "level": "warning",
    },
    "firewall_all_enabled": {
        "description": "All firewall profiles are enabled.",
        "level": "info",
    },
    "antivirus_not_detected": {
        "description": "No antivirus products detected.",
        "level": "critical",
    },
    "password_min_length_weak": {
        "description": "Minimum password length is weak (less than 8 characters).",
        "level": "warning",
    },
    "password_min_length_acceptable": {
        "description": "Minimum password length is acceptable (8–11 characters).",
        "level": "info",
    },
    "password_min_length_strong": {
        "description": "Minimum password length is strong (12+ characters).",
        "level": "info",
    },
    "password_complexity_disabled": {
        "description": "Password complexity requirements are disabled.",
        "level": "warning",
    },
    "password_complexity_enabled": {
        "description": "Password complexity requirements are enabled.",
        "level": "info",
    },
    "account_lockout_not_defined": {
        "description": "Account lockout policy is not defined.",
        "level": "warning",
    },
    "account_lockout_defined": {
        "description": "Account lockout policy is defined.",
        "level": "info",
    },
    "password_history_disabled": {
        "description": "Password history is not enforced.",
        "level": "warning",
    },
    "password_history_enabled": {
        "description": "Password history is enforced.",
        "level": "info",
    },
    "max_password_age_disabled": {
        "description": "Maximum password age is disabled.",
        "level": "warning",
    },
    "max_password_age_enabled": {
        "description": "Maximum password age is enabled.",
        "level": "info",
    },
    "max_password_age_too_long": {
        "description": "Maximum password age is too long (>365 days).",
        "level": "warning",
    },
    "smb_port_open": {
        "description": "SMB port 445 is open, which is common for Windows file sharing.",
        "level": "info",
    },
    "smb_port_risky": {
        "description": "SMB port 445 is open with public firewall disabled.",
        "level": "warning",
    },
    "high_risk_port_open": {
        "description": "High-risk port is open.",
        "level": "warning",
    },
    "suspicious_port_combination": {
        "description": "Insecure services exposed with firewall disabled.",
        "level": "critical",
    },
    "many_ports_open": {
        "description": "Large number of open ports detected.",
        "level": "warning",
    },
}
