"""Scanner module for system metrics.

Provides functions to retrieve system patch status, open TCP ports, and running services on Windows.
"""

import wmi
import psutil

c = wmi.WMI()


def get_patch_status():
    """Retrieve installed Windows hotfix identifiers and determine patch currency.

    Returns:
        dict: Contains 'hotfixes' (list of hotfix IDs) and 'status' ('up-to-date' or 'out-of-date').
    """
    hotfixes = [h.HotFixID for h in c.Win32_QuickFixEngineering()]
    status = "up-to-date" if hotfixes else "out-of-date"
    return {"hotfixes": hotfixes, "status": status}


def get_open_ports():
    """Retrieve all listening TCP ports on the system.

    Returns:
        dict: Contains 'ports' (sorted list of port numbers).
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
    """List all Windows services with their runtime state.

    Returns:
        dict: Contains 'services' (list of dicts with keys 'name' and 'state').
    """
    services = [{"name": s.Name, "state": s.State} for s in c.Win32_Service()]
    return {"services": services}
