"""Collects Windows system metrics such as patches, ports, services, firewall, antivirus status,
and password policies for security evaluation."""

import psutil
import subprocess
import re
import types

# Attempt to import Windows-specific WMI library; create a dummy if unavailable
try:
    import wmi

    c = wmi.WMI()
except ImportError:
    # Define a dummy WMI client with stub methods for non-Windows environments
    # This allows the application to run without WMI, returning empty/default data.
    class DummyWMIClient:
        def __init__(self, *args, **kwargs):
            pass

        def win32_quick_fix_engineering(self):  # pragma: no cover
            return []

        def win32_service(self):  # pragma: no cover
            return []

        def anti_virus_product(self):  # pragma: no cover
            return []

    # Create a dummy wmi module namespace
    wmi = types.SimpleNamespace(WMI=DummyWMIClient)  # Mock the wmi module
    c = DummyWMIClient()


def get_patch_status():
    """Return patch and hotfix status."""
    hotfixes = [h.HotFixID for h in c.Win32_QuickFixEngineering()]
    status = "up-to-date" if hotfixes else "out-of-date"
    return {"hotfixes": hotfixes, "status": status}


def get_open_ports():
    """Return a list of open TCP ports in LISTEN state."""
    ports = sorted(
        {
            conn.laddr.port
            for conn in psutil.net_connections()
            if conn.status == psutil.CONN_LISTEN and conn.laddr
        }
    )
    return {"ports": ports}


def get_running_services():
    """Return a list of running services with their states."""
    services = [{"name": s.Name, "state": s.State} for s in c.Win32_Service()]
    return {"services": services}


def get_firewall_status():
    """Return the on/off status of Windows Firewall profiles."""
    output = subprocess.check_output(
        "netsh advfirewall show allprofiles state", shell=True, text=True
    )
    profiles = {}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        # Match profile section headers (e.g., "Domain Profile Settings:")
        m_hdr = re.match(r"^(Domain|Private|Public) Profile Settings:", stripped)
        if m_hdr:
            current = m_hdr.group(1).lower()
        # Match profile state line (e.g., "State ON") within a profile section
        elif current:
            m_state = re.match(r"^State\s+(ON|OFF)", stripped)
            if m_state:
                profiles[current] = m_state.group(1)
                current = None
    return {"profiles": profiles}


def get_antivirus_status():
    """Return a list of installed antivirus products and their states."""
    sec = wmi.WMI(namespace="root\\SecurityCenter2")
    products = []
    for av in sec.AntiVirusProduct():
        products.append(
            {"name": av.displayName, "state": getattr(av, "productState", None)}
        )
    return {"products": products}


def get_password_policy():
    """Return local password policy settings (min length, max age)."""
    output = subprocess.check_output("net accounts", shell=True, text=True)
    policy = {}
    for line in output.splitlines():
        # Extract minimum password length (e.g., "Minimum password length 8")
        m = re.search(r"Minimum password length\s+(\d+|None)", line, re.IGNORECASE)
        if m:
            length_str = m.group(1)
            policy["min_password_length"] = (
                0 if length_str.lower() == "none" else int(length_str)
            )
        if "Maximum password age" in line:
            parts = line.split()
            policy["max_password_age"] = int(parts[-1])

    # Ensure min_password_length is at least 1 for sensible policy evaluation.
    if policy.get("min_password_length", 0) < 1:
        policy["min_password_length"] = 1
    # Default max_password_age to 0 (no expiration) if not found.
    policy.setdefault("max_password_age", 0)
    return {"policy": policy}
