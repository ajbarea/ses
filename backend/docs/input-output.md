# INPUT METRICS FROM SCANNING A WINDOWS 11 PC

```json
{
  "patch": {
    "hotfixes": ["KB5056579", "KB5048779", "KB5058499", "KB5059502"],
    "status": "up-to-date"
  },
  "ports": {
    "ports": [
      135, 139, 445, 5040, 5432, 5433, 6463, 7680, 8000, 49664, 49665, 49666,
      49667, 49668, 49676
    ]
  },
  "services": {
    "services": [
      { "name": "Appinfo", "state": "running" },
      { "name": "AppXSvc", "state": "running" },
      { "name": "AudioEndpointBuilder", "state": "running" },
      { "name": "Audiosrv", "state": "running" },
      { "name": "BFE", "state": "running" },
      { "name": "BrokerInfrastructure", "state": "running" },
      { "name": "BTAGService", "state": "running" },
      { "name": "BthAvctpSvc", "state": "running" },
      { "name": "bthserv", "state": "running" },
      { "name": "camsvc", "state": "running" },
      { "name": "CDPSvc", "state": "running" },
      { "name": "ClickToRunSvc", "state": "running" },
      { "name": "CoreMessagingRegistrar", "state": "running" },
      { "name": "CryptSvc", "state": "running" },
      { "name": "DcomLaunch", "state": "running" },
      { "name": "DeviceAssociationService", "state": "running" },
      { "name": "DeviceInstall", "state": "running" },
      { "name": "DevQueryBroker", "state": "running" },
      { "name": "Dhcp", "state": "running" },
      { "name": "DiagTrack", "state": "running" },
      { "name": "DispBrokerDesktopSvc", "state": "running" },
      { "name": "Dnscache", "state": "running" },
      { "name": "DoSvc", "state": "running" },
      { "name": "DPS", "state": "running" },
      { "name": "DusmSvc", "state": "running" },
      { "name": "EventLog", "state": "running" },
      { "name": "EventSystem", "state": "running" },
      { "name": "FontCache", "state": "running" },
      { "name": "GamingServices", "state": "running" },
      { "name": "GamingServicesNet", "state": "running" },
      { "name": "gpsvc", "state": "running" },
      { "name": "hidserv", "state": "running" },
      { "name": "hns", "state": "running" },
      { "name": "HvHost", "state": "running" },
      { "name": "InstallService", "state": "running" },
      { "name": "iphlpsvc", "state": "running" },
      { "name": "KeyIso", "state": "running" },
      { "name": "LanmanServer", "state": "running" },
      { "name": "LanmanWorkstation", "state": "running" },
      { "name": "lfsvc", "state": "running" },
      { "name": "LicenseManager", "state": "running" },
      { "name": "lmhosts", "state": "running" },
      { "name": "LSM", "state": "running" },
      { "name": "MDCoreSvc", "state": "running" },
      { "name": "mpssvc", "state": "running" },
      { "name": "NcbService", "state": "running" },
      { "name": "netprofm", "state": "running" },
      { "name": "NgcCtnrSvc", "state": "running" },
      { "name": "NgcSvc", "state": "running" },
      { "name": "nsi", "state": "running" },
      { "name": "nvagent", "state": "running" },
      { "name": "NvContainerLocalSystem", "state": "running" },
      { "name": "NVDisplay.ContainerLocalSystem", "state": "running" },
      { "name": "PcaSvc", "state": "running" },
      { "name": "PhoneSvc", "state": "running" },
      { "name": "PlexUpdateService", "state": "running" },
      { "name": "PlugPlay", "state": "running" },
      { "name": "postgresql-x64-16", "state": "running" },
      { "name": "postgresql-x64-17", "state": "running" },
      { "name": "Power", "state": "running" },
      { "name": "ProfSvc", "state": "running" },
      { "name": "QWAVE", "state": "running" },
      { "name": "RasMan", "state": "running" },
      { "name": "RmSvc", "state": "running" },
      { "name": "RpcEptMapper", "state": "running" },
      { "name": "RpcSs", "state": "running" },
      { "name": "SamSs", "state": "running" },
      { "name": "Schedule", "state": "running" },
      { "name": "SecurityHealthService", "state": "running" },
      { "name": "SENS", "state": "running" },
      { "name": "SharedAccess", "state": "running" },
      { "name": "ShellHWDetection", "state": "running" },
      { "name": "Spooler", "state": "running" },
      { "name": "SSDPSRV", "state": "running" },
      { "name": "SstpSvc", "state": "running" },
      { "name": "StateRepository", "state": "running" },
      { "name": "StiSvc", "state": "running" },
      { "name": "StorSvc", "state": "running" },
      { "name": "SysMain", "state": "running" },
      { "name": "SystemEventsBroker", "state": "running" },
      { "name": "TextInputManagementService", "state": "running" },
      { "name": "Themes", "state": "running" },
      { "name": "TimeBrokerSvc", "state": "running" },
      { "name": "TokenBroker", "state": "running" },
      { "name": "TrkWks", "state": "running" },
      { "name": "TrustedInstaller", "state": "running" },
      { "name": "UserManager", "state": "running" },
      { "name": "UsoSvc", "state": "running" },
      { "name": "VaultSvc", "state": "running" },
      { "name": "W32Time", "state": "running" },
      { "name": "Wcmsvc", "state": "running" },
      { "name": "wcncsvc", "state": "running" },
      { "name": "WdNisSvc", "state": "running" },
      { "name": "WinDefend", "state": "running" },
      { "name": "WinHttpAutoProxySvc", "state": "running" },
      { "name": "Winmgmt", "state": "running" },
      { "name": "WlanSvc", "state": "running" },
      { "name": "WpnService", "state": "running" },
      { "name": "WSAIFabricSvc", "state": "running" },
      { "name": "wscsvc", "state": "running" },
      { "name": "WSearch", "state": "running" },
      { "name": "WSLService", "state": "running" },
      { "name": "wuauserv", "state": "running" },
      { "name": "BluetoothUserService_17ba4d6", "state": "running" },
      { "name": "cbdhsvc_17ba4d6", "state": "running" },
      { "name": "CDPUserSvc_17ba4d6", "state": "running" },
      { "name": "DevicesFlowUserSvc_17ba4d6", "state": "running" },
      { "name": "NPSMSvc_17ba4d6", "state": "running" },
      { "name": "OneSyncSvc_17ba4d6", "state": "running" },
      { "name": "UdkUserSvc_17ba4d6", "state": "running" },
      { "name": "webthreatdefusersvc_17ba4d6", "state": "running" },
      { "name": "WpnUserService_17ba4d6", "state": "running" }
    ]
  },
  "firewall": {
    "profiles": { "domain": "ON", "private": "ON", "public": "ON" }
  },
  "antivirus": {
    "products": [{ "name": "Windows Defender", "state": 397568 }]
  },
  "password_policy": {
    "policy": { "max_password_age": 42, "min_password_length": 1 }
  }
}
```

## RESPONSE RETURNED FROM EXPERT SYSTEM

```json
{
  "score": 100,
  "grade": "Excellent",
  "summary": "Antivirus software is properly configured with up-to-date definitions and real-time protection.; All firewall profiles are enabled.; SMB port 445 is open, which is common for Windows file sharing.; System patches are up-to-date.",
  "impact_summary": "4 neutral findings. ",
  "findings": [
    {
      "rule": "antivirus_properly_configured",
      "level": "info",
      "description": "Antivirus software is properly configured with up-to-date definitions and real-time protection.",
      "recommendation": "Continue monitoring antivirus status and keep definitions updated.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)"
    },
    {
      "rule": "firewall_all_enabled",
      "level": "info",
      "description": "All firewall profiles are enabled.",
      "recommendation": "Continue monitoring firewall status.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)"
    },
    {
      "rule": "smb_port_open",
      "level": "info",
      "description": "SMB port 445 is open, which is common for Windows file sharing.",
      "recommendation": "Ensure this port is not exposed to the internet and is properly firewalled.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)",
      "details": [445]
    },
    {
      "rule": "patch_status",
      "level": "info",
      "description": "System patches are up-to-date.",
      "recommendation": "Continue with regular patch management.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)",
      "details": ["KB5056579", "KB5048779", "KB5058499", "KB5059502"]
    }
  ],
  "positive_findings": [],
  "negative_findings": [],
  "neutral_findings": [
    {
      "rule": "antivirus_properly_configured",
      "level": "info",
      "description": "Antivirus software is properly configured with up-to-date definitions and real-time protection.",
      "recommendation": "Continue monitoring antivirus status and keep definitions updated.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)"
    },
    {
      "rule": "firewall_all_enabled",
      "level": "info",
      "description": "All firewall profiles are enabled.",
      "recommendation": "Continue monitoring firewall status.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)"
    },
    {
      "rule": "smb_port_open",
      "level": "info",
      "description": "SMB port 445 is open, which is common for Windows file sharing.",
      "recommendation": "Ensure this port is not exposed to the internet and is properly firewalled.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)",
      "details": [445]
    },
    {
      "rule": "patch_status",
      "level": "info",
      "description": "System patches are up-to-date.",
      "recommendation": "Continue with regular patch management.",
      "score_impact": { "value": 0, "type": "neutral" },
      "score_text": "0 points (neutral)",
      "details": ["KB5056579", "KB5048779", "KB5058499", "KB5059502"]
    }
  ],
  "rules_fired": 5,
  "explanations": [
    {
      "rule": "antivirus_properly_configured",
      "activation": "Rule activated: antivirus_properly_configured - Antivirus software is properly configured with up-to-date definitions and real-time protection."
    },
    {
      "rule": "firewall_all_enabled",
      "activation": "Rule activated: firewall_all_enabled - All firewall profiles are enabled."
    },
    {
      "rule": "smb_port_open",
      "activation": "Rule activated: smb_port_open - SMB port 445 is open, which is common for Windows file sharing."
    },
    {
      "rule": "patch_status",
      "activation": "Rule activated: patch_status - System patches are up-to-date."
    }
  ],
  "timestamp": "2025-06-10T23:04:30.268164+00:00",
  "metrics": {
    "patch": {
      "hotfixes": ["KB5056579", "KB5048779", "KB5058499", "KB5059502"],
      "status": "up-to-date"
    },
    "ports": {
      "ports": [
        135, 139, 445, 5040, 5432, 5433, 6463, 7680, 8000, 49664, 49665, 49666,
        49667, 49668, 49676
      ]
    },
    "services": {
      "services": [
        { "name": "Appinfo", "state": "running" },
        { "name": "AppXSvc", "state": "running" },
        { "name": "AudioEndpointBuilder", "state": "running" },
        { "name": "Audiosrv", "state": "running" },
        { "name": "BFE", "state": "running" },
        { "name": "BrokerInfrastructure", "state": "running" },
        { "name": "BTAGService", "state": "running" },
        { "name": "BthAvctpSvc", "state": "running" },
        { "name": "bthserv", "state": "running" },
        { "name": "camsvc", "state": "running" },
        { "name": "CDPSvc", "state": "running" },
        { "name": "ClickToRunSvc", "state": "running" },
        { "name": "CoreMessagingRegistrar", "state": "running" },
        { "name": "CryptSvc", "state": "running" },
        { "name": "DcomLaunch", "state": "running" },
        { "name": "DeviceAssociationService", "state": "running" },
        { "name": "DeviceInstall", "state": "running" },
        { "name": "DevQueryBroker", "state": "running" },
        { "name": "Dhcp", "state": "running" },
        { "name": "DiagTrack", "state": "running" },
        { "name": "DispBrokerDesktopSvc", "state": "running" },
        { "name": "Dnscache", "state": "running" },
        { "name": "DoSvc", "state": "running" },
        { "name": "DPS", "state": "running" },
        { "name": "DusmSvc", "state": "running" },
        { "name": "EventLog", "state": "running" },
        { "name": "EventSystem", "state": "running" },
        { "name": "FontCache", "state": "running" },
        { "name": "GamingServices", "state": "running" },
        { "name": "GamingServicesNet", "state": "running" },
        { "name": "gpsvc", "state": "running" },
        { "name": "hidserv", "state": "running" },
        { "name": "hns", "state": "running" },
        { "name": "HvHost", "state": "running" },
        { "name": "InstallService", "state": "running" },
        { "name": "iphlpsvc", "state": "running" },
        { "name": "KeyIso", "state": "running" },
        { "name": "LanmanServer", "state": "running" },
        { "name": "LanmanWorkstation", "state": "running" },
        { "name": "lfsvc", "state": "running" },
        { "name": "LicenseManager", "state": "running" },
        { "name": "lmhosts", "state": "running" },
        { "name": "LSM", "state": "running" },
        { "name": "MDCoreSvc", "state": "running" },
        { "name": "mpssvc", "state": "running" },
        { "name": "NcbService", "state": "running" },
        { "name": "netprofm", "state": "running" },
        { "name": "NgcCtnrSvc", "state": "running" },
        { "name": "NgcSvc", "state": "running" },
        { "name": "nsi", "state": "running" },
        { "name": "nvagent", "state": "running" },
        { "name": "NvContainerLocalSystem", "state": "running" },
        { "name": "NVDisplay.ContainerLocalSystem", "state": "running" },
        { "name": "PcaSvc", "state": "running" },
        { "name": "PhoneSvc", "state": "running" },
        { "name": "PlexUpdateService", "state": "running" },
        { "name": "PlugPlay", "state": "running" },
        { "name": "postgresql-x64-16", "state": "running" },
        { "name": "postgresql-x64-17", "state": "running" },
        { "name": "Power", "state": "running" },
        { "name": "ProfSvc", "state": "running" },
        { "name": "QWAVE", "state": "running" },
        { "name": "RasMan", "state": "running" },
        { "name": "RmSvc", "state": "running" },
        { "name": "RpcEptMapper", "state": "running" },
        { "name": "RpcSs", "state": "running" },
        { "name": "SamSs", "state": "running" },
        { "name": "Schedule", "state": "running" },
        { "name": "SecurityHealthService", "state": "running" },
        { "name": "SENS", "state": "running" },
        { "name": "SharedAccess", "state": "running" },
        { "name": "ShellHWDetection", "state": "running" },
        { "name": "Spooler", "state": "running" },
        { "name": "SSDPSRV", "state": "running" },
        { "name": "SstpSvc", "state": "running" },
        { "name": "StateRepository", "state": "running" },
        { "name": "StiSvc", "state": "running" },
        { "name": "StorSvc", "state": "running" },
        { "name": "SysMain", "state": "running" },
        { "name": "SystemEventsBroker", "state": "running" },
        { "name": "TextInputManagementService", "state": "running" },
        { "name": "Themes", "state": "running" },
        { "name": "TimeBrokerSvc", "state": "running" },
        { "name": "TokenBroker", "state": "running" },
        { "name": "TrkWks", "state": "running" },
        { "name": "TrustedInstaller", "state": "running" },
        { "name": "UserManager", "state": "running" },
        { "name": "UsoSvc", "state": "running" },
        { "name": "VaultSvc", "state": "running" },
        { "name": "W32Time", "state": "running" },
        { "name": "Wcmsvc", "state": "running" },
        { "name": "wcncsvc", "state": "running" },
        { "name": "WdNisSvc", "state": "running" },
        { "name": "WinDefend", "state": "running" },
        { "name": "WinHttpAutoProxySvc", "state": "running" },
        { "name": "Winmgmt", "state": "running" },
        { "name": "WlanSvc", "state": "running" },
        { "name": "WpnService", "state": "running" },
        { "name": "WSAIFabricSvc", "state": "running" },
        { "name": "wscsvc", "state": "running" },
        { "name": "WSearch", "state": "running" },
        { "name": "WSLService", "state": "running" },
        { "name": "BluetoothUserService_17ba4d6", "state": "running" },
        { "name": "cbdhsvc_17ba4d6", "state": "running" },
        { "name": "CDPUserSvc_17ba4d6", "state": "running" },
        { "name": "DevicesFlowUserSvc_17ba4d6", "state": "running" },
        { "name": "NPSMSvc_17ba4d6", "state": "running" },
        { "name": "OneSyncSvc_17ba4d6", "state": "running" },
        { "name": "UdkUserSvc_17ba4d6", "state": "running" },
        { "name": "webthreatdefusersvc_17ba4d6", "state": "running" },
        { "name": "WpnUserService_17ba4d6", "state": "running" }
      ]
    },
    "firewall": {
      "profiles": { "domain": "ON", "private": "ON", "public": "ON" }
    },
    "antivirus": {
      "products": [{ "name": "Windows Defender", "state": 397568 }]
    },
    "password_policy": {
      "policy": { "max_password_age": 42, "min_password_length": 1 }
    }
  }
}
```
