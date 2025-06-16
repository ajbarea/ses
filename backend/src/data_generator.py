"""Module for generating synthetic security metrics for Windows systems."""

import secrets
from pathlib import Path
import csv
import argparse
import json
from typing import Dict, List, Any


def generate_patch_metric() -> Dict[str, Any]:
    """
    Generate a patch metric with random status and hotfix list.

    Returns:
        dict: Contains 'status' (patch state) and 'hotfixes' (list of hotfix identifiers).
    """
    status_choices = ["up-to-date", "out-of-date"]
    hotfix_strategies = [
        [],
        ["KB5056579", "KB5048779"],
        ["KB5058499", "KB5059502", "KB5055555", "KB5066666"],
        ["KB1234567", "KB2345678", "KB3456789"],
    ]
    return {
        "status": secrets.choice(status_choices),
        "hotfixes": secrets.choice(hotfix_strategies),
    }


def generate_ports_metric() -> Dict[str, Any]:
    """
    Generate an open ports metric with a random selection of port numbers.

    Returns:
        dict: Contains 'ports' mapping to a list of port numbers.
    """
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
        [21, 22, 23, 25, 53, 80, 110, 135, 137, 139, 443, 445, 3389, 5900],  # High risk
    ]
    return {"ports": secrets.choice(port_strategies)}


def generate_services_metric() -> Dict[str, Any]:
    """
    Generate a metric representing Windows services with random statuses.

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


def generate_firewall_metric() -> Dict[str, Any]:
    """
    Generate a firewall metric with random profile states.

    Returns:
        dict: Contains 'profiles', a dict with 'domain', 'private', and 'public' statuses.
    """
    scenarios = [
        {"domain": "ON", "private": "ON", "public": "ON"},  # All enabled
        {"domain": "ON", "private": "ON", "public": "OFF"},  # Public disabled
        {"domain": "OFF", "private": "OFF", "public": "OFF"},  # All disabled (risky)
        {"domain": "UNKNOWN", "private": "ON", "public": "ON"},  # Domain unknown
    ]
    return {"profiles": secrets.choice(scenarios)}


def generate_antivirus_metric() -> Dict[str, Any]:
    """
    Generate an antivirus metric with random product information.

    Returns:
        dict: Contains 'products', a list of antivirus product dictionaries.
    """
    scenarios = [
        [],  # No products
        [{"name": "Windows Defender", "state": 397568}],  # Fully enabled
        [{"name": "Windows Defender", "state": 397312}],  # Enabled different config
        [{"name": "Windows Defender", "state": 262144}],  # Disabled
        [{"name": "Windows Defender", "state": "UNKNOWN"}],  # Unknown state
    ]
    return {"products": secrets.choice(scenarios)}


def generate_password_policy_metric() -> Dict[str, Any]:
    """
    Generate a password policy metric with random settings.

    Returns:
        dict: Contains 'policy', a dictionary with password policy settings.
    """
    scenarios = [
        {"min_password_length": 0, "max_password_age": 0},  # No policy enforcement
        {"min_password_length": 1, "max_password_age": 42},  # Minimal enforcement
        {"min_password_length": 6, "max_password_age": 90},  # Basic security
        {"min_password_length": 8, "max_password_age": 60},  # Medium security
        {"min_password_length": 12, "max_password_age": 90},  # High security
    ]
    return {"policy": secrets.choice(scenarios)}


def generate_single_metric_set() -> Dict[str, Any]:
    """
    Generate a comprehensive set of security metrics.

    Returns:
        dict: All security metrics organized by category.
    """
    return {
        "patch": generate_patch_metric(),
        "ports": generate_ports_metric(),
        "services": generate_services_metric(),
        "firewall": generate_firewall_metric(),
        "antivirus": generate_antivirus_metric(),
        "password_policy": generate_password_policy_metric(),
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
            break

    # Flatten password policy metrics
    policy = metrics_dict.get("password_policy", {}).get("policy", {})
    flat["password_min_length"] = policy.get("min_password_length", 0)
    flat["password_max_age"] = policy.get("max_password_age", 0)

    return flat


def generate_dataset(expert_system, num_samples: int) -> List[Dict[str, Any]]:
    """
    Generate a dataset by evaluating generated metrics with the expert system.

    Args:
        expert_system: An instance capable of evaluating security metrics.
        num_samples (int): Number of samples to generate.

    Returns:
        List[dict]: List of dataset rows with flattened metrics and evaluation targets.
    """
    dataset = []
    print(f"Generating {num_samples} samples...")

    for i in range(num_samples):
        if (i + 1) % 100 == 0:
            print(f"Progress: {i+1}/{num_samples}")

        metrics = generate_single_metric_set()
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
    return dataset


def save_to_csv(dataset: List[Dict[str, Any]], filepath: Path):
    """
    Save the dataset to a CSV file.

    Args:
        dataset (List[dict]): The dataset to save.
        filepath (Path): The output CSV file path.
    """
    if not dataset:
        print("Dataset is empty.")
        return

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
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

    args = parser.parse_args()

    try:
        from .clips_evaluator import SecurityExpertSystem

        # Initialize expert system
        rules_path = Path(__file__).parent / "clips_rules"
        expert_system = SecurityExpertSystem(rules_dir=str(rules_path))
        print("Expert system initialized.")

        # Generate dataset
        dataset = generate_dataset(expert_system, args.num_samples)

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
