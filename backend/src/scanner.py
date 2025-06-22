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
import platform

# Detect the current platform
CURRENT_PLATFORM = platform.system()
IS_WINDOWS = CURRENT_PLATFORM == "Windows"

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
    try:
        ports = sorted(
            {
                conn.laddr.port
                for conn in psutil.net_connections()
                if conn.status == psutil.CONN_LISTEN and conn.laddr
            }
        )
        return {"ports": ports}
    except Exception as e:  # pragma: no cover
        # On macOS and other non-Windows platforms, this might require elevated permissions
        # Return empty list to allow the app to continue functioning
        if IS_WINDOWS:
            print(f"Warning: Unable to get open ports due to error: {e}")
        else:
            print(
                f"Warning: Unable to get open ports on {CURRENT_PLATFORM} - may require elevated permissions or be unsupported: {e}"
            )
        return {"ports": []}


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
    try:
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
    except (subprocess.CalledProcessError, OSError) as e:  # pragma: no cover
        # netsh command is Windows-specific and will fail on other platforms
        if IS_WINDOWS:
            print(f"Warning: Unable to get firewall status: {e}")
        else:
            print(
                f"Warning: Firewall status not available on {CURRENT_PLATFORM} (Windows-specific feature)"
            )
        return {
            "profiles": {"domain": "UNKNOWN", "private": "UNKNOWN", "public": "UNKNOWN"}
        }


def get_antivirus_status():
    """Get information about installed antivirus products.

    Uses Windows Security Center WMI interface to identify installed
    antivirus products and their status.

    Returns:
        dict: Contains 'products' list with name and state information
    """
    try:
        sec = wmi.WMI(namespace="root\\SecurityCenter2")
        products = []
        for av in sec.AntiVirusProduct():
            products.append(
                {"name": av.displayName, "state": getattr(av, "productState", None)}
            )
        return {"products": products}
    except Exception as e:  # pragma: no cover
        # WMI is Windows-specific and will fail on other platforms
        if IS_WINDOWS:
            print(f"Warning: Unable to get antivirus status: {e}")
        else:
            print(
                f"Warning: Antivirus status not available on {CURRENT_PLATFORM} (Windows-specific feature)"
            )
        return {"products": []}


def get_password_policy():
    """Get Windows password policy settings.

    Uses 'net accounts' command to retrieve password policy information
    such as minimum length and maximum age.

    Returns:
        dict: Contains 'policy' dict with password policy settings
    """
    try:
        output = subprocess.check_output("net accounts", shell=True, text=True)
        policy = {}

        # Define the patterns we care about, the policy key, and how to convert the match
        rules = [
            (
                "min_password_length",
                r"Minimum password length\s+(\d+|None)",
                lambda v: 0 if v.lower() == "none" else int(v),
            ),
            (
                "max_password_age",
                r"Maximum password age\s+(\d+|Never)",
                lambda v: "disabled" if v.lower() == "never" else int(v),
            ),
            ("min_password_age", r"Minimum password age\s+(\d+)", lambda v: int(v)),
            (
                "history_size",
                r"Password history length\s+(\d+|None)",
                lambda v: 0 if v.lower() == "none" else int(v),
            ),
            (
                "lockout_threshold",
                r"Lockout threshold\s+(\d+|Never)",
                lambda v: "not-defined" if v.lower() == "never" else int(v),
            ),
            (
                "complexity",
                r"Password complexity requirements\s+(Enabled|Disabled)",
                lambda v: v.lower(),
            ),
        ]

        for line in output.splitlines():
            for key, pattern, transformer in rules:
                m = re.search(pattern, line, re.IGNORECASE)
                if not m:
                    continue
                policy[key] = transformer(m.group(1))
                break  # move to next line once one rule is matched

        # Post-processing defaults and sanity checks
        # Ensure min_password_length is at least 1
        policy["min_password_length"] = max(policy.get("min_password_length", 1), 1)
        # Default max_password_age to 0 (no expiration) if not set
        policy.setdefault("max_password_age", 0)

        return {"policy": policy}
    except (subprocess.CalledProcessError, OSError) as e:  # pragma: no cover
        # 'net accounts' command is Windows-specific and will fail on other platforms
        if IS_WINDOWS:
            print(f"Warning: Unable to get password policy: {e}")
        else:
            print(
                f"Warning: Password policy not available on {CURRENT_PLATFORM} (Windows-specific feature)"
            )
        return {"policy": {"min_password_length": 1, "max_password_age": 0}}
