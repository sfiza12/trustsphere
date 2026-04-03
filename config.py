import os
import yaml  # type: ignore
import logging

def load_config():
    """
    Loads configuration constants from config.yaml into a dictionary.
    Includes error handling for missing file or invalid yaml.
    """
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found at {config_path}")
        # Fallback to defaults to prevent immediate application crash
        return {}
    except yaml.YAMLError as exc:  # type: ignore
        logging.error(f"Error parsing config.yaml: {exc}")
        return {}

# Load it once into memory
config = load_config()

# Provide direct access via python variables for easy imports
# ML Constants
ML_THRESHOLD = config.get('ml_threshold', 0.75)
ML_MODERATE_THRESHOLD = config.get('ml_moderate_threshold', 0.60)
MIN_DEVIATING_PARAMS = config.get('min_deviating_params', 2)
PARAM_Z_THRESHOLD = config.get('param_z_threshold', 5.0)
DEVICE_BASELINES = config.get('device_baselines', {
    'SENSOR_01': [20, 1, 443, 1],
    'THERMOSTAT_02': [50, 2, 443, 1],
    'CAM_03': [100, 2, 443, 1],
    'BULB_04': [5, 0, 443, 1],
    'ROUTER_05': [150, 4, 443, 3]
})

# Hard Violation
APPROVED_PORTS = config.get('approved_ports', [80, 443, 8080, 22, 21])
APPROVED_IP_PREFIXES = config.get('approved_ip_prefixes', ['192.168.', '10.0.', '172.16.', '13.107.', '8.8.'])
MAX_FAILED_CONNECTIONS = config.get('max_failed_connections', 50)
HARD_TRAFFIC_CAP = config.get('hard_traffic_cap', 500)

# Drift Detection
SPIKE_THRESHOLD = config.get('spike_threshold', 0.50)
DRIFT_THRESHOLD = config.get('drift_threshold', 0.30)
SUSTAINED_HOURS = config.get('sustained_hours', 6)

# Baseline Manager
DRIFT_HOURS_BEFORE_CONFIRMATION = config.get('drift_hours_before_confirmation', 6)
CONFIRMATION_HOURS_REQUIRED = config.get('confirmation_hours_required', 6)
BASELINE_SHIFT_RATE = config.get('baseline_shift_rate', 0.10)

# Trust Score
DIMENSION_CAP = config.get('dimension_cap', 30)
RECOVERY_PER_CLEAN_HOUR = config.get('recovery_per_clean_hour', 5)

# System
DATABASE_PATH = config.get('database_path', 'trustsphere.db')
