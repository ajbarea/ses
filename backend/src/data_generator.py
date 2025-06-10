import random
from pathlib import Path
import csv
import argparse # Added argparse
# from .clips_evaluator import SecurityExpertSystem # Moved import to main block

def generate_patch_metric():
    """Generates a patch metric with detailed logic."""
    status_choices = ["up-to-date", "out-of-date"]
    hotfix_strategies = [
        [],
        ["KB123456", "KB789012"],
        ["KB111111", "KB222222", "KB333333", "KB444444"],
    ]
    chosen_status = random.choice(status_choices)
    chosen_hotfixes = random.choice(hotfix_strategies)
    return {"status": chosen_status, "hotfixes": chosen_hotfixes}

def generate_ports_metric():
    """Generates a ports metric with detailed logic."""
    port_list_strategies = [
        [],
        [80, 443],
        [21, 22, 80, 443, 3389],
        [21, 22, 23, 25, 53, 80, 110, 135, 137, 139, 443, 445, 3389, 5900],
    ]
    chosen_ports_list = random.choice(port_list_strategies)
    return {"ports": chosen_ports_list}

def generate_services_metric():
    """Generates a services metric with detailed logic."""
    service_list_strategies = [
        [],
        [{"name": "dnsClient", "state": "Running"}, {"name": "RemoteRegistry", "state": "Stopped"}, {"name": "Spooler", "state": "Running"}],
        [{"name": f"GenericService{i}", "state": random.choice(["Running", "Stopped"])} for i in range(50)],
        [{"name": f"GenericService{i}", "state": random.choice(["Running", "Stopped"])} for i in range(350)],
    ]
    chosen_services_list = random.choice(service_list_strategies)
    return {"services": chosen_services_list}

def generate_firewall_metric():
    """Generates a firewall metric with detailed logic."""
    profile_states = ["ON", "OFF", "UNKNOWN"]
    domain_state = random.choice(profile_states)
    private_state = random.choice(profile_states)
    public_state = random.choice(profile_states)
    return {"profiles": {"domain": domain_state, "private": private_state, "public": public_state}}

def generate_antivirus_metric():
    """Generates an antivirus metric with detailed logic."""
    av_product_scenarios = [
        [], # No products
        [{"name": "Windows Defender", "state": random.choice([397312, 262144, "UNKNOWN", None])}], # One product
        [{"name": "Defender", "state": 397312}, {"name": "VendorAV", "state": 397568}], # All enabled
        [{"name": "Defender", "state": 397312}, {"name": "VendorAV", "state": 262144}], # Mixed
        [{"name": "Defender", "state": 262144}, {"name": "VendorAV", "state": 0}], # All disabled (0 can be another form of disabled/not active)
        [{"name": "Defender", "state": 262144}, {"name": "VendorAV", "state": None}], # One disabled, one unknown
    ]
    chosen_av_products_list = random.choice(av_product_scenarios)
    return {"products": chosen_av_products_list}

def generate_password_policy_metric():
    """Generates a password policy metric with detailed logic."""
    min_len_choices = [0, 6, 8, 10, 12, 14]
    max_age_choices = [0, 30, 60, 90, 180, 365] # 0 can mean not set or no expiration
    min_len = random.choice(min_len_choices)
    max_age = random.choice(max_age_choices)
    return {"policy": {"min_password_length": min_len, "max_password_age": max_age}}

def generate_single_metric_set():
    """Generates a single set of metrics using detailed generators."""
    metrics = {
        "patch_metric": generate_patch_metric(),
        "ports_metric": generate_ports_metric(),
        "services_metric": generate_services_metric(),
        "firewall_metric": generate_firewall_metric(),
        "antivirus_metric": generate_antivirus_metric(),
        "password_policy_metric": generate_password_policy_metric(),
    }
    return metrics

def generate_multiple_metric_sets(num_samples: int):
    """Generates multiple sets of metrics."""
    return [generate_single_metric_set() for _ in range(num_samples)]

def flatten_metrics(metrics_dict: dict) -> dict:
    """Flattens the nested metrics dictionary for CSV output."""
    flat = {}
    if "patch_metric" in metrics_dict and metrics_dict["patch_metric"]:
        flat["patch_status"] = metrics_dict["patch_metric"].get("status", "unknown")
        flat["patch_hotfixes_count"] = len(metrics_dict["patch_metric"].get("hotfixes", []))
    else:
        flat["patch_status"] = "unknown"
        flat["patch_hotfixes_count"] = 0

    if "ports_metric" in metrics_dict and metrics_dict["ports_metric"]:
        flat["ports_count"] = len(metrics_dict["ports_metric"].get("ports", []))
    else:
        flat["ports_count"] = 0

    if "services_metric" in metrics_dict and metrics_dict["services_metric"]:
        flat["services_count"] = len(metrics_dict["services_metric"].get("services", []))
    else:
        flat["services_count"] = 0

    if "firewall_metric" in metrics_dict and metrics_dict["firewall_metric"] and metrics_dict["firewall_metric"].get("profiles"):
        profiles = metrics_dict["firewall_metric"]["profiles"]
        flat["firewall_domain_status"] = profiles.get("domain", "UNKNOWN")
        flat["firewall_private_status"] = profiles.get("private", "UNKNOWN")
        flat["firewall_public_status"] = profiles.get("public", "UNKNOWN")
    else:
        flat["firewall_domain_status"] = "UNKNOWN"
        flat["firewall_private_status"] = "UNKNOWN"
        flat["firewall_public_status"] = "UNKNOWN"

    if "antivirus_metric" in metrics_dict and metrics_dict["antivirus_metric"]:
        flat["antivirus_products_count"] = len(metrics_dict["antivirus_metric"].get("products", []))
        # Note: A more detailed antivirus status (enabled/disabled/partial) would require
        # deeper inspection or access to how SecurityExpertSystem derives this.
        # For now, product count is a direct metric.
    else:
        flat["antivirus_products_count"] = 0

    if "password_policy_metric" in metrics_dict and metrics_dict["password_policy_metric"] and metrics_dict["password_policy_metric"].get("policy"):
        policy = metrics_dict["password_policy_metric"]["policy"]
        flat["password_policy_min_length"] = policy.get("min_password_length", 0)
        flat["password_policy_max_age"] = policy.get("max_password_age", 0)
    else:
        flat["password_policy_min_length"] = 0
        flat["password_policy_max_age"] = 0

    return flat

def generate_dataset(expert_system: "SecurityExpertSystem", num_samples: int): # Use string literal for type hint
    """
    Generates a dataset of metrics and their corresponding expert system evaluations.
    Each entry in the dataset is a flat dictionary ready for CSV.
    """
    dataset = []
    print(f"Generating {num_samples} dataset entries...")
    for i in range(num_samples):
        if (i + 1) % 100 == 0 :
            print(f"Generating entry {i+1}/{num_samples}")
        metrics = generate_single_metric_set()
        result = expert_system.evaluate(metrics)

        flat_data_row = flatten_metrics(metrics)

        if result and 'score' in result and 'grade' in result:
            flat_data_row["score"] = result['score']
            flat_data_row["grade"] = result['grade']
        else:
            flat_data_row["score"] = None
            flat_data_row["grade"] = "Error"

        dataset.append(flat_data_row)
    print("Dataset generation complete.")
    return dataset

def save_to_csv(dataset: list[dict], filepath: Path):
    """Saves the dataset (list of flat dicts) to a CSV file."""
    if not dataset:
        print("Dataset is empty. No CSV file will be created.")
        return

    try:
        headers = dataset[0].keys()
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(dataset)
        print(f"Dataset successfully saved to {filepath.resolve()}")
    except IOError as e:
        print(f"Error saving dataset to CSV: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during CSV saving: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a dataset of system security metrics and their CLIPS expert system evaluations.")
    parser.add_argument(
        "-n", "--num_samples",
        type=int,
        default=100,
        help="Number of metric samples to generate. Default is 100."
    )
    parser.add_argument(
        "-o", "--output_file",
        type=str,
        default="es_security_dataset.csv",
        help="Path for the output CSV file. Default is 'es_security_dataset.csv' in the current working directory."
    )
    args = parser.parse_args()

    # Use Path object for output_file for consistency
    output_filepath = Path(args.output_file)
    # rules_path should be relative to this script's location (backend/src/clips_rules)
    rules_path = Path(__file__).parent / "clips_rules"

    # Moved SecurityExpertSystem import here
    try:
        from .clips_evaluator import SecurityExpertSystem

        print("Initializing SecurityExpertSystem...")
        expert_system_instance = SecurityExpertSystem(rules_path=rules_path)
        print(f"SecurityExpertSystem initialized. Rules loaded from: {rules_path.resolve()}")

        print(f"Attempting to generate dataset with {args.num_samples} samples...")
        generated_data = generate_dataset(expert_system_instance, args.num_samples)

        if generated_data:
            print(f"\n--- First few generated data entries (flat format) ---")
            for i, data_entry in enumerate(generated_data[:3]): # Print first 3 samples
                print(f"Entry {i+1}: {data_entry}")
            print("-" * 20)

            print(f"Attempting to save dataset to {output_filepath.resolve()}...")
            save_to_csv(generated_data, output_filepath)
        else:
            print("No data was generated. CSV file will not be created.")

    except ImportError as e:
        print(f"Error: {e}")
        print("This is likely due to 'clipspy' not being available in the environment.")
        print("Please ensure CLIPS/clipspy is installed and accessible.")
        print("Dataset generation and CSV export aborted.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("Dataset generation and CSV export aborted.")
