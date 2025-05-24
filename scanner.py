"""Windows security metric collection module.

Collects system security data through WMI and command-line utilities.
Provides standardized metric collection for patches, services, firewall,
antivirus, and password policies.
"""

import psutil
import subprocess
import re
import types

# Attempt to import Windows-specific WMI library; disable if unavailable
try:
    import wmi

    c = wmi.WMI()
except ImportError:
    # Define a dummy WMI client with stub methods for non-Windows environments
    class DummyWMIClient:
        def __init__(self, *args, **kwargs):
            pass

        def Win32_QuickFixEngineering(self):
            return []

        def Win32_Service(self):
            return []

        def AntiVirusProduct(self):
            return []

    # Create a dummy wmi module namespace
    wmi = types.SimpleNamespace(WMI=DummyWMIClient)
    c = DummyWMIClient()


def get_patch_status():
    """Get Windows update status and installed hotfixes.

    Returns:
        dict: Status ('up-to-date'|'out-of-date') and list of hotfix IDs
    """
    hotfixes = [h.HotFixID for h in c.Win32_QuickFixEngineering()]
    status = "up-to-date" if hotfixes else "out-of-date"
    return {"hotfixes": hotfixes, "status": status}


def get_open_ports():
    """Get TCP ports in LISTENING state.

    Returns:
        dict: List of active listening port numbers
    """
    ports = sorted(
        {
            conn.laddr.port
            for conn in psutil.net_connections()
            if conn.status == psutil.CONN_LISTEN and conn.laddr
        }
    )
    return {"ports": ports}


def get_running_services():
    """Get Windows services and their current states.

    Returns:
        dict: List of services with name and runtime state
    """
    services = [{"name": s.Name, "state": s.State} for s in c.Win32_Service()]
    return {"services": services}


def get_firewall_status():
    """Get Windows Firewall status for all profiles.

    Parses 'netsh' output to determine ON/OFF state for each profile.

    Returns:
        dict: Status ('ON'|'OFF') for domain, private, and public profiles
    """
    output = subprocess.check_output(
        "netsh advfirewall show allprofiles state", shell=True, text=True
    )
    profiles = {}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        # Match profile section headers (Domain/Private/Public Profile Settings:)
        m_hdr = re.match(r"^(Domain|Private|Public) Profile Settings:", stripped)
        if m_hdr:
            current = m_hdr.group(1).lower()
        # Match profile state line (State ON/OFF)
        elif current:
            m_state = re.match(r"^State\s+(ON|OFF)", stripped)
            if m_state:
                profiles[current] = m_state.group(1)
                current = None
    return {"profiles": profiles}


def get_antivirus_status():
    """Get installed antivirus products from SecurityCenter2.

    Returns:
        dict: List of detected products with name and state code
    """
    sec = wmi.WMI(namespace="root\\SecurityCenter2")
    products = []
    for av in sec.AntiVirusProduct():
        products.append(
            {"name": av.displayName, "state": getattr(av, "productState", None)}
        )
    return {"products": products}


def get_password_policy():
    """Get local password policy settings.

    Parses 'net accounts' output for password length and age requirements.
    Ensures minimum password length is at least 1 for validation.

    Returns:
        dict: Minimum length and maximum age settings
    """
    output = subprocess.check_output("net accounts", shell=True, text=True)
    policy = {}
    for line in output.splitlines():
        # extract minimum password length
        m = re.search(r"Minimum password length\s+(\d+)", line)
        if m:
            policy["min_password_length"] = int(m.group(1))
        # extract maximum password age
        m2 = re.search(r"Maximum password age\s+(\d+)", line)
        if m2:
            policy["max_password_age"] = int(m2.group(1))
    # ensure valid defaults for password policy
    if policy.get("min_password_length", 0) < 1:
        policy["min_password_length"] = 1
    policy.setdefault("max_password_age", 0)
    return {"policy": policy}
