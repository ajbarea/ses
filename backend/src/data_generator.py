"""Module for generating synthetic security metrics for Windows systems."""

import secrets
from pathlib import Path
import csv
import argparse
import json
from typing import Dict, List, Any

# Constants
WINDOWS_DEFENDER = "Windows Defender"


def generate_patch_metric(excellent_bias: bool = False) -> Dict[str, Any]:
    """
    Generate a patch metric with weighted realistic status distribution.

    Args:
        excellent_bias: If True, bias toward excellent security configurations.

    Returns:
        dict: Contains 'status' (patch state) and 'hotfixes' (list of hotfix identifiers).
    """
    if excellent_bias:
        # For excellent systems, strongly favor up-to-date patches
        status_weights = [("up-to-date", 9), ("out-of-date", 1)]
    else:
        status_weights = [("up-to-date", 7), ("out-of-date", 3)]

    weighted_statuses = []
    for status, weight in status_weights:
        weighted_statuses.extend([status] * weight)

    if excellent_bias:
        # Excellent systems typically have some hotfixes applied
        hotfix_strategies = [
            ["KB5056579", "KB5048779"],
            ["KB5058499", "KB5059502", "KB5055555", "KB5066666"],
            ["KB1234567", "KB2345678", "KB3456789"],
        ]
    else:
        hotfix_strategies = [
            [],
            ["KB5056579", "KB5048779"],
            ["KB5058499", "KB5059502", "KB5055555", "KB5066666"],
            ["KB1234567", "KB2345678", "KB3456789"],
        ]
    return {
        "status": secrets.choice(weighted_statuses),
        "hotfixes": secrets.choice(hotfix_strategies),
    }


def generate_ports_metric(excellent_bias: bool = False) -> Dict[str, Any]:
    """
    Generate an open ports metric with a random selection of port numbers.

    Args:
        excellent_bias: If True, bias toward excellent security configurations.

    Returns:
        dict: Contains 'ports' mapping to a list of port numbers.
    """
    if excellent_bias:
        # Excellent systems have minimal open ports - only essential services
        port_strategies = [
            [],  # No open ports (most secure)
            [80, 443],  # Only web services
            [135, 139, 445],  # Windows file sharing only
        ]
    else:
        port_strategies = [
            [],
            [80, 443],
            [135, 139, 445],  # Windows file sharing
            [135, 139, 445, 3389],  # + RDP
            [135, 139, 445, 5432, 5433],  # + PostgreSQL
            [135, 139, 445, 5040, 5432, 5433, 6463, 7680, 8000],
            [
                135,
                139,
                445,
                5040,
                5432,
                5433,
                6463,
                7680,
                8000,
                49664,
                49665,
                49666,
                49667,
                49668,
                49676,
            ],
            [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                135,
                137,
                139,
                443,
                445,
                3389,
                5900,
            ],  # High risk
        ]
    return {"ports": secrets.choice(port_strategies)}


def generate_services_metric(excellent_bias: bool = False) -> Dict[str, Any]:
    """
    Generate a metric representing Windows services with random statuses.

    Args:
        excellent_bias: If True, bias toward excellent security configurations.

    Returns:
        dict: Contains 'services', a list of dictionaries each with 'name' and 'state'.
    """
    windows_services = [
        "Appinfo",
        "AppXSvc",
        "AudioEndpointBuilder",
        "Audiosrv",
        "BFE",
        "BrokerInfrastructure",
        "BTAGService",
        "BthAvctpSvc",
        "bthserv",
        "camsvc",
        "CDPSvc",
        "ClickToRunSvc",
        "CoreMessagingRegistrar",
        "CryptSvc",
        "DcomLaunch",
        "DeviceAssociationService",
        "DeviceInstall",
        "DevQueryBroker",
        "Dhcp",
        "DiagTrack",
        "DispBrokerDesktopSvc",
        "Dnscache",
        "DoSvc",
        "DPS",
        "DusmSvc",
        "EventLog",
        "EventSystem",
        "FontCache",
        "GamingServices",
        "GamingServicesNet",
        "gpsvc",
        "hidserv",
        "hns",
        "HvHost",
        "InstallService",
        "iphlpsvc",
        "KeyIso",
        "LanmanServer",
        "LanmanWorkstation",
        "lfsvc",
        "LicenseManager",
        "lmhosts",
        "LSM",
        "MDCoreSvc",
        "mpssvc",
        "NcbService",
        "netprofm",
        "NgcCtnrSvc",
        "NgcSvc",
        "nsi",
        "nvagent",
        "NvContainerLocalSystem",
        "PcaSvc",
        "PhoneSvc",
        "PlexUpdateService",
        "PlugPlay",
        "postgresql-x64-16",
        "postgresql-x64-17",
        "Power",
        "ProfSvc",
        "QWAVE",
        "RasMan",
        "RmSvc",
        "RpcEptMapper",
        "RpcSs",
        "SamSs",
        "Schedule",
        "SecurityHealthService",
        "SENS",
        "SharedAccess",
        "ShellHWDetection",
        "Spooler",
        "SSDPSRV",
        "SstpSvc",
        "StateRepository",
        "StiSvc",
        "Themes",
        "TimeBrokerSvc",
        "TokenBroker",
        "TrkWks",
        "TrustedInstaller",
        "UserManager",
        "UsoSvc",
        "VaultSvc",
        "W32Time",
        "Wcmsvc",
        "wcncsvc",
        "WdNisSvc",
        "WinDefend",
        "WinHttpAutoProxySvc",
        "Winmgmt",
        "WlanSvc",
        "WpnService",
        "WSAIFabricSvc",
        "wscsvc",
        "WSearch",
        "WSLService",
        "wuauserv",
    ]

    # Use secrets for cryptographically secure shuffling
    shuffled = []
    services_copy = list(windows_services)
    while services_copy:
        # Select and remove a random service from the copy
        index = secrets.randbelow(len(services_copy))
        shuffled.append(services_copy.pop(index))
    shuffled_services_for_medium_set = shuffled

    selected_services_for_medium_set = shuffled_services_for_medium_set[
        : min(30, len(windows_services))
    ]
    medium_set_services = [
        {"name": service, "state": secrets.choice(["running", "stopped"])}
        for service in selected_services_for_medium_set
    ]

    if excellent_bias:
        # Excellent systems typically have controlled service counts and good configurations
        service_strategies = [
            [],  # No services (lean system)
            # Small, well-managed set
            [
                {"name": "Dnscache", "state": "running"},
                {"name": "Spooler", "state": "running"},
            ],
            # Medium set with mostly running services (well-maintained)
            [
                {
                    "name": service,
                    "state": (
                        "running" if secrets.randbelow(10) > 2 else "stopped"
                    ),  # 70% running
                }
                for service in selected_services_for_medium_set[:15]  # Smaller set
            ],
        ]
    else:
        service_strategies = [
            [],  # No services
            # Small set
            [
                {"name": "Dnscache", "state": "running"},
                {"name": "Spooler", "state": "running"},
            ],
            # Medium set
            medium_set_services,
            # Large set
            [
                {
                    "name": service,
                    "state": "running" if secrets.randbelow(10) > 0 else "stopped",
                }
                for service in windows_services
            ],
        ]
    return {"services": secrets.choice(service_strategies)}


def generate_firewall_metric(excellent_bias: bool = False) -> Dict[str, Any]:
    """
    Generate a firewall metric with realistic weighted profile states.

    Args:
        excellent_bias: If True, bias toward excellent security configurations.

    Returns:
        dict: Contains 'profiles', a dict with 'domain', 'private', and 'public' statuses.
    """
    if excellent_bias:
        # Excellent systems have firewalls properly configured
        scenarios_weighted = [
            (
                {"domain": "ON", "private": "ON", "public": "ON"},
                8,
            ),  # 80% - All enabled (most secure)
            (
                {"domain": "ON", "private": "ON", "public": "OFF"},
                2,
            ),  # 20% - Public disabled but still secure
        ]
    else:
        # More realistic distribution - most systems have some firewall protection
        scenarios_weighted = [
            (
                {"domain": "ON", "private": "ON", "public": "ON"},
                4,
            ),  # 40% - All enabled (most secure)
            (
                {"domain": "ON", "private": "ON", "public": "OFF"},
                3,
            ),  # 30% - Public disabled (common)
            (
                {"domain": "UNKNOWN", "private": "ON", "public": "ON"},
                2,
            ),  # 20% - Domain unknown
            (
                {"domain": "OFF", "private": "OFF", "public": "OFF"},
                1,
            ),  # 10% - All disabled (risky)
        ]

    weighted_scenarios = []
    for scenario, weight in scenarios_weighted:
        weighted_scenarios.extend([scenario] * weight)

    return {"profiles": secrets.choice(weighted_scenarios)}


def generate_antivirus_metric(excellent_bias: bool = False) -> Dict[str, Any]:
    """
    Generate an antivirus metric with realistic weighted product information.

    Args:
        excellent_bias: If True, bias toward excellent security configurations.

    Returns:
        dict: Contains 'products', a list of antivirus product dictionaries.
    """
    if excellent_bias:
        # Excellent systems have properly configured antivirus
        scenarios_weighted = [
            ([{"name": WINDOWS_DEFENDER, "state": 397568}], 7),  # 70% - Fully enabled
            (
                [{"name": WINDOWS_DEFENDER, "state": 397312}],
                3,
            ),  # 30% - Enabled different config
        ]
    else:
        # More realistic distribution - most systems have some antivirus
        scenarios_weighted = [
            ([{"name": WINDOWS_DEFENDER, "state": 397568}], 4),  # 40% - Fully enabled
            (
                [{"name": WINDOWS_DEFENDER, "state": 397312}],
                3,
            ),  # 30% - Enabled different config
            ([{"name": WINDOWS_DEFENDER, "state": 262144}], 2),  # 20% - Disabled
            (
                [{"name": WINDOWS_DEFENDER, "state": "UNKNOWN"}],
                1,
            ),  # 10% - Unknown state
            ([], 0),  # 0% - No products (very rare)
        ]

    weighted_scenarios = []
    for scenario, weight in scenarios_weighted:
        if weight > 0:  # Only include scenarios with positive weight
            weighted_scenarios.extend([scenario] * weight)

    return {"products": secrets.choice(weighted_scenarios)}


def generate_password_policy_metric(excellent_bias: bool = False) -> Dict[str, Any]:
    """
    Generate a password policy metric with realistic weighted settings.

    Args:
        excellent_bias: If True, bias toward excellent security configurations.

    Returns:
        dict: Contains 'policy', a dictionary with password policy settings.
    """
    if excellent_bias:
        # Excellent systems have strong password policies with all security features enabled
        scenarios_weighted = [
            (
                {
                    "min_password_length": 12,
                    "max_password_age": 90,
                    "complexity": "enabled",
                    "lockout_threshold": 5,
                    "history_size": 12,
                },
                4,
            ),  # 40% - Comprehensive strong policy
            (
                {
                    "min_password_length": 14,
                    "max_password_age": 60,
                    "complexity": "enabled",
                    "lockout_threshold": 3,
                    "history_size": 10,
                },
                3,
            ),  # 30% - Very strong policy
            (
                {
                    "min_password_length": 10,
                    "max_password_age": 90,
                    "complexity": "enabled",
                    "lockout_threshold": 5,
                    "history_size": 8,
                },
                2,
            ),  # 20% - Good comprehensive policy
            (
                {
                    "min_password_length": 8,
                    "max_password_age": 60,
                    "complexity": "enabled",
                    "lockout_threshold": 5,
                    "history_size": 5,
                },
                1,
            ),  # 10% - Minimal but complete policy
        ]
    else:
        # More realistic distribution - most corporate systems have some password policy
        scenarios_weighted = [
            (
                {
                    "min_password_length": 8,
                    "max_password_age": 60,
                    "complexity": "enabled",
                    "lockout_threshold": 5,
                    "history_size": 5,
                },
                2,
            ),  # 20% - Good complete policy
            (
                {
                    "min_password_length": 12,
                    "max_password_age": 90,
                    "complexity": "disabled",
                    "lockout_threshold": "not-defined",
                    "history_size": 0,
                },
                2,
            ),  # 20% - Strong length but missing features
            (
                {
                    "min_password_length": 6,
                    "max_password_age": 90,
                    "complexity": "disabled",
                    "lockout_threshold": 3,
                    "history_size": 3,
                },
                2,
            ),  # 20% - Moderate policy
            (
                {
                    "min_password_length": 1,
                    "max_password_age": 42,
                    "complexity": "disabled",
                    "lockout_threshold": "not-defined",
                    "history_size": 0,
                },
                2,
            ),  # 20% - Weak policy
            (
                {
                    "min_password_length": 0,
                    "max_password_age": 0,
                    "complexity": "disabled",
                    "lockout_threshold": "not-defined",
                    "history_size": 0,
                },
                2,
            ),  # 20% - No policy (risky)
        ]

    weighted_scenarios = []
    for scenario, weight in scenarios_weighted:
        weighted_scenarios.extend([scenario] * weight)

    return {"policy": secrets.choice(weighted_scenarios)}


def generate_single_metric_set(excellent_bias: bool = False) -> Dict[str, Any]:
    """
    Generate a comprehensive set of security metrics.

    Args:
        excellent_bias: If True, bias toward excellent security configurations.

    Returns:
        dict: All security metrics organized by category.
    """
    return {
        "patch": generate_patch_metric(excellent_bias),
        "ports": generate_ports_metric(excellent_bias),
        "services": generate_services_metric(excellent_bias),
        "firewall": generate_firewall_metric(excellent_bias),
        "antivirus": generate_antivirus_metric(excellent_bias),
        "password_policy": generate_password_policy_metric(excellent_bias),
    }


def flatten_metrics(metrics_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten nested metrics into a single-level dictionary for CSV output.

    Args:
        metrics_dict (dict): Nested metrics dictionary.

    Returns:
        dict: Flattened metrics with scalar values.
    """
    flat = {}

    # Flatten patch metrics
    patch = metrics_dict.get("patch", {})
    flat["patch_status"] = patch.get("status", "unknown")
    flat["patch_hotfixes_count"] = len(patch.get("hotfixes", []))

    # Flatten ports metrics
    ports = metrics_dict.get("ports", {}).get("ports", [])
    flat["ports_count"] = len(ports)

    # Flatten services metrics
    services = metrics_dict.get("services", {}).get("services", [])
    flat["services_total"] = len(services)
    flat["services_running"] = len([s for s in services if s.get("state") == "running"])
    flat["services_stopped"] = len([s for s in services if s.get("state") == "stopped"])

    # Flatten firewall metrics
    profiles = metrics_dict.get("firewall", {}).get("profiles", {})
    flat["firewall_domain"] = profiles.get("domain", "UNKNOWN")
    flat["firewall_private"] = profiles.get("private", "UNKNOWN")
    flat["firewall_public"] = profiles.get("public", "UNKNOWN")

    # Flatten antivirus metrics
    av_products = metrics_dict.get("antivirus", {}).get("products", [])
    flat["antivirus_count"] = len(av_products)
    flat["antivirus_enabled"] = 0
    for product in av_products:
        state = product.get("state")
        if isinstance(state, int) and state >= 397312:
            flat["antivirus_enabled"] = 1
            break  # Flatten password policy metrics
    policy = metrics_dict.get("password_policy", {}).get("policy", {})
    flat["password_min_length"] = policy.get("min_password_length", 0)
    flat["password_max_age"] = policy.get("max_password_age", 0)
    flat["password_complexity"] = policy.get("complexity", "disabled")
    flat["password_lockout_threshold"] = policy.get("lockout_threshold", "not-defined")
    flat["password_history_size"] = policy.get("history_size", 0)

    return flat


def generate_dataset(
    expert_system, num_samples: int, excellent_percentage: float = 0.25
) -> List[Dict[str, Any]]:
    """
    Generate a dataset by evaluating generated metrics with the expert system.

    Args:
        expert_system: An instance capable of evaluating security metrics.
        num_samples (int): Number of samples to generate.
        excellent_percentage (float): Percentage of samples to generate with excellent bias (0.0-1.0).

    Returns:
        List[dict]: List of dataset rows with flattened metrics and evaluation targets.
    """
    dataset = []
    print(f"Generating {num_samples} samples...")
    print(
        f"Using excellent bias for {excellent_percentage*100:.1f}% of samples to increase 'Excellent' grades"
    )

    excellent_count = int(num_samples * excellent_percentage)

    for i in range(num_samples):
        if (i + 1) % 100 == 0:
            print(f"Progress: {i+1}/{num_samples}")

        # Use excellent bias for first portion of samples
        use_excellent_bias = i < excellent_count

        metrics = generate_single_metric_set(excellent_bias=use_excellent_bias)
        result = expert_system.evaluate(metrics)
        row = flatten_metrics(metrics)

        # Add evaluation targets
        if result and "score" in result and "grade" in result:
            row["target_score"] = result["score"]
            row["target_grade"] = result["grade"]
        else:
            row["target_score"] = None
            row["target_grade"] = "Error"

        dataset.append(row)

    print("Dataset generation complete.")

    # Print grade distribution for verification
    grade_counts = {}
    for row in dataset:
        grade = row.get("target_grade", "Unknown")
        grade_counts[grade] = grade_counts.get(grade, 0) + 1

    print("\nGenerated grade distribution:")
    for grade, count in sorted(grade_counts.items()):
        percentage = (count / len(dataset)) * 100
        print(f"  {grade}: {count} ({percentage:.1f}%)")

    return dataset


def save_to_csv(dataset: List[Dict[str, Any]], filepath: Path):
    """
    Save the dataset to a CSV file.

    Args:
        dataset (List[dict]): The dataset to save.
        filepath (Path): The output CSV file path.
    """
    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            if not dataset:
                return
            writer = csv.DictWriter(csvfile, fieldnames=list(dataset[0].keys()))
            writer.writeheader()
            writer.writerows(dataset)
        print(f"Dataset saved to {filepath}")
    except Exception as e:
        print(f"Error saving CSV: {e}")


def split_dataset(
    dataset: List[Dict[str, Any]], train_ratio: float
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Split the dataset into training and testing sets.

    Args:
        dataset (List[dict]): The complete dataset.
        train_ratio (float): Proportion of data to use for training (e.g., 0.8).

    Returns:
        tuple: (training dataset, testing dataset).
    """
    split_idx = int(len(dataset) * train_ratio)
    return dataset[:split_idx], dataset[split_idx:]


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser(description="Generate dataset for ML training.")
    parser.add_argument(
        "-n",
        "--num_samples",
        type=int,
        default=1000,
        help="Number of samples to generate (default: 1000)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="security_dataset.csv",
        help="Output CSV file (default: security_dataset.csv)",
    )
    parser.add_argument(
        "--split", type=float, help="Train/test split ratio (e.g., 0.8 for 80% train)"
    )
    parser.add_argument(
        "--excellent_percentage",
        type=float,
        default=0.25,
        help="Percentage of samples to generate with excellent bias (0.0-1.0, default: 0.25)",
    )

    args = parser.parse_args()

    try:
        from .clips_evaluator import SecurityExpertSystem

        # Initialize expert system
        rules_path = Path(__file__).parent / "clips_rules"
        expert_system = SecurityExpertSystem(rules_dir=str(rules_path))
        print("Expert system initialized.")

        # Generate dataset
        dataset = generate_dataset(
            expert_system, args.num_samples, args.excellent_percentage
        )

        if not dataset:
            print("No data generated.")
            exit(1)

        # Save dataset
        output_path = Path(args.output)

        if args.split and 0 < args.split < 1:
            # Split and save train/test sets
            train_data, test_data = split_dataset(dataset, args.split)

            train_path = output_path.with_stem(f"{output_path.stem}_train")
            test_path = output_path.with_stem(f"{output_path.stem}_test")

            save_to_csv(train_data, train_path)
            save_to_csv(test_data, test_path)

            print(f"Split: {len(train_data)} train, {len(test_data)} test samples")
        else:
            # Save complete dataset
            save_to_csv(dataset, output_path)

        print("\nSample row:")
        if dataset:
            sample = {k: v for i, (k, v) in enumerate(dataset[0].items()) if i < 8}
            print(json.dumps(sample, indent=2))

    except ImportError as e:
        print(f"Error importing expert system: {e}")
    except Exception as e:
        print(f"Error: {e}")
