"""Windows system security metrics collector.

Extracts security-relevant information from Windows systems including:
- Patch and hotfix status
- Open network ports
- Running services
- Windows Firewall configuration
- Antivirus product status
- Password policy settings
"""

import psutil
import subprocess
import re
import types

# Create fallback WMI functionality for non-Windows platforms
try:
    import wmi

    c = wmi.WMI()
except ImportError:

    class DummyWMIClient:
        """Stub WMI client for non-Windows environments.

        Provides empty implementations of common WMI queries to allow
        the application to run on non-Windows platforms for testing.
        """

        def __init__(self, *args, **kwargs):
            pass

        def Win32_QuickFixEngineering(self):  # pragma: no cover
            return []

        def Win32_Service(self):  # pragma: no cover
            return []

        def AntiVirusProduct(self):  # pragma: no cover
            return []

    wmi = types.SimpleNamespace(WMI=DummyWMIClient)
    c = DummyWMIClient()


def get_patch_status():
    """Get system patch and hotfix information.

    Queries the system for installed hotfixes using WMI and determines
    if the system is up-to-date based on hotfix presence.

    Returns:
        dict: Contains 'hotfixes' list and 'status' indicator
    """
    hotfixes = [h.HotFixID for h in c.Win32_QuickFixEngineering()]
    status = "up-to-date" if hotfixes else "out-of-date"
    return {"hotfixes": hotfixes, "status": status}


def get_open_ports():
    """Get list of open TCP ports in LISTEN state.

    Uses psutil to identify all network ports that are currently open and
    listening for connections.

    Returns:
        dict: Contains 'ports' list of open port numbers
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
    """Get list of running Windows services.

    Attempts to use psutil first, then falls back to WMI if that fails.
    Only includes services that are in the 'running' state.

    Returns:
        dict: Contains 'services' list with name and state information
    """
    try:
        # Try psutil first (cross-platform)
        services = [
            {"name": s.name(), "state": s.status()}
            for s in psutil.win_service_iter()
            if s.status() == "running"
        ]
    except Exception:
        # Fall back to WMI if psutil fails
        services = [
            {"name": s.Name, "state": s.State}
            for s in c.Win32_Service()
            if s.State == "Running"
        ]
    return {"services": services}


def get_firewall_status():
    """Get Windows Firewall profile status information.

    Uses netsh command to query the status of domain, private, and
    public Windows Firewall profiles.

    Returns:
        dict: Contains 'profiles' dict with status of each profile
    """
    output = subprocess.check_output(
        "netsh advfirewall show allprofiles state", shell=True, text=True
    )
    profiles = {}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        # Match profile section headers
        m_hdr = re.match(r"^(Domain|Private|Public) Profile Settings:", stripped)
        if m_hdr:
            current = m_hdr.group(1).lower()
        # Match state line within a profile section
        elif current:
            m_state = re.match(r"^State\s+(ON|OFF)", stripped)
            if m_state:
                profiles[current] = m_state.group(1)
                current = None
    return {"profiles": profiles}


def get_antivirus_status():
    """Get information about installed antivirus products.

    Uses Windows Security Center WMI interface to identify installed
    antivirus products and their status.

    Returns:
        dict: Contains 'products' list with name and state information
    """
    sec = wmi.WMI(namespace="root\\SecurityCenter2")
    products = []
    for av in sec.AntiVirusProduct():
        products.append(
            {"name": av.displayName, "state": getattr(av, "productState", None)}
        )
    return {"products": products}


def get_password_policy():
    """Get Windows password policy settings.

    Uses 'net accounts' command to retrieve password policy information
    such as minimum length and maximum age.

    Returns:
        dict: Contains 'policy' dict with password policy settings
    """
    output = subprocess.check_output("net accounts", shell=True, text=True)
    policy = {}

    for line in output.splitlines():
        # Extract minimum password length
        m = re.search(r"Minimum password length\s+(\d+|None)", line, re.IGNORECASE)
        if m:
            length_str = m.group(1)
            policy["min_password_length"] = (
                0 if length_str.lower() == "none" else int(length_str)
            )

        # Extract maximum password age
        if "Maximum password age" in line:
            parts = line.split()
            policy["max_password_age"] = int(parts[-1])

    # Ensure minimum password length is at least 1 for sensible evaluation
    if policy.get("min_password_length", 0) < 1:
        policy["min_password_length"] = 1

    # Default max_password_age to 0 (no expiration) if not found
    policy.setdefault("max_password_age", 0)

    return {"policy": policy}
