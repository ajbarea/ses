# Security Evaluation System Documentation

This document provides a comprehensive overview of the core security assessment components in the SES application, including metric collection, rule evaluation, scoring mechanisms, and rule descriptions.

## Overview

The Security Evaluation System is built around a modular architecture that separates concerns between data collection, rule evaluation, and scoring. The system supports both a basic Python-based rule engine and an advanced CLIPS expert system, providing flexibility and graceful degradation.

## Metric Collection (`scanner.py`)

The `scanner.py` module serves as the primary interface for collecting security-relevant information from Windows systems. It provides a unified API for gathering various system metrics while handling platform compatibility and error conditions gracefully.

### Key Features

- **Cross-platform compatibility**: Uses fallback mechanisms for non-Windows environments
- **WMI integration**: Leverages Windows Management Instrumentation for system queries
- **Robust error handling**: Graceful degradation when components are unavailable
- **Comprehensive coverage**: Collects data across multiple security domains

### Metric Categories

#### Patch Status (`get_patch_status()`)

Collects information about system updates and hotfixes:

```python
{
    "hotfixes": ["KB5056579", "KB5048779", "KB5058499"],
    "status": "up-to-date"  # or "out-of-date"
}
```

**Implementation Details:**

- Queries `Win32_QuickFixEngineering` WMI class
- Determines status based on presence of hotfixes
- Returns empty list for non-Windows platforms

#### Network Ports (`get_open_ports()`)

Identifies open TCP ports in LISTEN state:

```python
{
    "ports": [80, 135, 139, 443, 445, 3389, 5432]
}
```

**Implementation Details:**

- Uses `psutil.net_connections()` for cross-platform compatibility
- Filters for LISTEN state connections only
- Sorts port numbers for consistent output

#### Running Services (`get_running_services()`)

Enumerates active Windows services:

```python
{
    "services": [
        {"name": "Dnscache", "state": "running"},
        {"name": "Spooler", "state": "running"},
        {"name": "WinDefend", "state": "running"}
    ]
}
```

**Implementation Details:**

- Primary method uses `psutil.win_service_iter()`
- Falls back to WMI `Win32_Service` queries if psutil fails
- Filters for running services only

#### Firewall Configuration (`get_firewall_status()`)

Retrieves Windows Firewall profile states:

```python
{
    "profiles": {
        "domain": "ON",
        "private": "ON",
        "public": "OFF"
    }
}
```

**Implementation Details:**

- Executes `netsh advfirewall show allprofiles state` command
- Parses output using regular expressions
- Handles different profile section formats

#### Antivirus Status (`get_antivirus_status()`)

Queries installed antivirus products:

```python
{
    "products": [
        {
            "name": "Windows Defender",
            "state": 397568  # Product state bitmask
        }
    ]
}
```

**Implementation Details:**

- Accesses `root\SecurityCenter2` WMI namespace
- Queries `AntiVirusProduct` class
- Extracts product names and state information

#### Password Policy (`get_password_policy()`)

Retrieves system password policy settings:

```python
{
    "policy": {
        "min_password_length": 8,
        "max_password_age": 90,
        "min_password_age": 1,
        "history_size": 12,
        "lockout_threshold": 5,
        "complexity": "enabled"
    }
}
```

**Implementation Details:**

- Executes `net accounts` command
- Uses pattern matching to extract policy values
- Applies defaults and validation rules

### Error Handling and Fallbacks

The scanner implements several fallback mechanisms:

1. **Platform Detection**: Creates dummy WMI client for non-Windows systems
2. **Method Alternatives**: Multiple approaches for service enumeration
3. **Graceful Degradation**: Returns safe defaults when queries fail
4. **Type Validation**: Ensures consistent data types in responses

## Rule Evaluation (`rules.py`)

The `rules.py` module implements the basic Python-based rule engine that serves as the fallback evaluation system. It provides deterministic scoring based on predefined security criteria.

### Core Functions

#### Security Score Calculation

The rule engine uses a simple scoring approach:

- **Fixed Scoring**: Returns consistent scores based on rule evaluation
- **Binary Assessment**: Issues are either present or absent
- **Threshold-Based**: Uses predefined criteria for each metric category

#### Rule Categories

Based on the actual implementation, the basic rule engine provides:

**Evaluation Logic:**

- Processes collected metrics through evaluation functions
- Applies security assessment criteria
- Generates findings with descriptions and recommendations
- Assigns security grades based on overall assessment

**Assessment Areas:**

- Patch status evaluation
- Network port risk assessment
- Service configuration analysis
- Firewall state validation
- Antivirus protection verification
- Password policy strength checking

### Grade Assignment

Security grades are assigned based on evaluation results:

- **Excellent**: Strong security posture across all areas
- **Good**: Generally secure with minor issues
- **Fair**: Moderate security with some concerns
- **Poor**: Significant security weaknesses present
- **Critical Risk**: Serious security vulnerabilities detected

## Evaluation System Integration

### Evaluation Flow

1. **Metric Collection**: `scanner.py` gathers system information
2. **Engine Selection**: System chooses between CLIPS and basic evaluation
3. **Rule Processing**: Selected engine processes metrics
4. **Result Generation**: Findings and scores are produced
5. **Response Formatting**: Results formatted for API response

### Dual Engine Support

The system supports both evaluation approaches:

```python
def evaluate(metrics, use_clips=None):
    """Main evaluation entry point with engine selection."""
    if should_use_clips_engine(use_clips):
        return _evaluate_clips(metrics)
    else:
        return _evaluate_legacy(metrics)
```

### Error Handling Strategy

- **Graceful Degradation**: Falls back to basic rules if CLIPS fails
- **Comprehensive Logging**: Error reporting for debugging
- **Safe Defaults**: Returns minimal viable results on failures
- **User Communication**: Clear error messages when appropriate

## Rule Descriptions (`rule_descriptions.py`)

This module provides human-readable descriptions and remediation guidance for security findings.

### Finding Categories

#### Critical Findings

High-impact security issues requiring immediate attention:

- **Firewall Disabled**: "Windows Firewall is disabled, leaving system exposed"
- **No Antivirus**: "No antivirus protection detected on system"
- **Weak Passwords**: "Password policy allows weak passwords"

#### Warning Findings

Moderate security concerns that should be addressed:

- **Open High-Risk Ports**: "High-risk network ports are exposed"
- **Outdated System**: "System is missing security updates"
- **Excessive Services**: "Too many services are running"

#### Informational Findings

Configuration notes and best practice recommendations:

- **Strong Firewall**: "Firewall is properly configured"
- **Updated System**: "System is up to date with patches"
- **Good Password Policy**: "Strong password policy is enforced"

### Remediation Guidance

Each finding includes specific remediation steps:

```python
REMEDIATION_GUIDE = {
    "firewall_disabled": {
        "steps": [
            "Open Windows Security settings",
            "Navigate to Firewall & network protection",
            "Enable firewall for all network profiles",
            "Configure appropriate firewall rules"
        ],
        "urgency": "immediate",
        "difficulty": "easy"
    }
}
```

## Integration Architecture

### Architecture Flow

1. **Metric Collection**: `scanner.py` gathers system information
2. **Rule Selection**: System chooses between CLIPS and basic rules
3. **Evaluation**: Selected engine processes metrics and generates findings
4. **Scoring**: Results are scored and graded consistently
5. **Reporting**: Findings are enriched with descriptions and guidance

### Dual Engine Implementation

The system supports both evaluation engines seamlessly:

```python
def evaluate(metrics, use_clips=None):
    """Main evaluation entry point with engine selection."""
    if should_use_clips_engine(use_clips):
        return _evaluate_clips(metrics)
    else:
        return _evaluate_legacy(metrics)
```

### Extended Error Handling Strategy

- **Graceful Degradation**: Falls back to basic rules if CLIPS fails
- **Comprehensive Logging**: Detailed error reporting for debugging
- **Safe Defaults**: Returns minimal viable results on critical failures
- **User Communication**: Clear error messages for end users
