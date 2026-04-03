# =============================================================================
# ML ANOMALY MODULE — TrustSphere
# =============================================================================
# This module implements an unsupervised Machine Learning anomaly detection engine.
# It uses the Isolation Forest algorithm to establish a behavioral baseline for 
# each unique device and flags deviations. 
# 
# KEY DESIGN PRINCIPLE:
# It detects MULTI-PARAMETER anomalies only. This means that a single metric 
# spiking (e.g., just packet count) is not enough to flag an ML anomaly. At least 
# MIN_DEVIATING_PARAMS (e.g., 2) dimensions must deviate simultaneously to 
# indicate a coordinated anomaly or compromise.
# =============================================================================

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# -----------------------------------------------------------------------------
# CONFIGURATION CONSTANTS
# -----------------------------------------------------------------------------
# ML_THRESHOLD: The required normalized anomaly score (0.0 to 1.0) to trigger 
# a HIGH anomaly penalty level.
ML_THRESHOLD          = 0.75

# ML_MODERATE_THRESHOLD: The required normalized anomaly score to trigger a 
# MODERATE anomaly penalty level.
ML_MODERATE_THRESHOLD = 0.60

# MIN_DEVIATING_PARAMS: The absolute minimum number of distinct network parameters
# (e.g., packets, failed connections, port, unique IPs) that must statistically
# deviate from the norm before the ML model will even evaluate an anomaly score.
# This prevents noise on a single axis from crushing the trust score.
MIN_DEVIATING_PARAMS  = 2

# PARAM_Z_THRESHOLD: The z-score (standard deviations from the mean) required 
# for a single parameter to be considered "deviating". A z-score of 5.0 is highly 
# statistically significant, ensuring only extreme deviations count towards the 
# MIN_DEVIATING_PARAMS requirement.
PARAM_Z_THRESHOLD     = 5.0

# DEVICE_BASELINES: Hardcoded fallback baseline values for known device types. 
# Used to seed the initial training history if real pre-training data is sparse.
# Format: 'DEVICE_ID': (packets_per_min, failed_connections, port_used, unique_ips)
DEVICE_BASELINES = {
    'SENSOR_01':     (20,   1,  443, 1),
    'THERMOSTAT_02': (50,   2,  443, 1),
    'CAM_03':        (100,  2,  443, 1),
    'BULB_04':       (5,    0,  443, 1),
    'ROUTER_05':     (150,  4,  443, 3),
}

# _device_models: Module-level dictionary acting as an in-memory cache to store 
# the instantiated and trained DeviceMLModel objects for each distinct device_id. 
# This ensures we don't re-train models from scratch on every telemetry row.
_device_models = {}


class DeviceMLModel:
    """
    A class that encapsulates the Machine Learning logic, state, and Isolation 
    Forest model for a single specific IoT device. Maintains its own training 
    history, scaler, and baseline statistics.
    """
    def __init__(self, device_id):
        self.device_id = device_id
        
        # StandardScaler is used to normalize the feature vectors (packets, failed, 
        # port, ips) so that parameters with vastly different scales (e.g., port 443 
        # vs. 1 failed connection) don't distort the Isolation Forest's distance metrics.
        self.scaler = StandardScaler()
        
        # The core anomaly detection algorithm. 
        # n_estimators=100: Number of base estimators in the ensemble.
        # contamination=0.05: The expected proportion of outliers in the data set.
        # random_state=42: Ensures reproducible, consistent deterministic results.
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        
        self.is_trained = False
        self.training_history = []
        
        # To store the calculated mean and standard deviation of each feature post-training.
        # Used for z-score calculations to determine individual parameter deviation.
        self.feature_means = None
        self.feature_stds  = None
        
        # Automatically preload synthetic baseline data and train the model
        # so it's ready to handle immediate predictions without erroring out.
        self._preload_and_train()

    def _generate_baseline(self):
        """
        Generates 30 rows of synthetic, semi-random baseline data to 'warm up'
        the model. This gives the Isolation Forest an initial concept of 'normal' 
        behavior based on the hardcoded DEVICE_BASELINES profile.
        """
        if self.device_id in DEVICE_BASELINES:
            # Unpack the hardcoded baseline template for this specific device
            bp, bf, bport, bips = DEVICE_BASELINES[self.device_id]
        else:
            # Fallback default baseline if the device ID is universally unknown
            bp, bf, bport, bips = 50, 5, 443, 2
            
        np.random.seed(42)  # For reproducible generation
        rows = []
        for _ in range(30):
            # Introduce slight organic noise/jitter around the baseline values
            # to prevent the model from overfitting to literally identical static values.
            rows.append([
                bp * np.random.uniform(0.90, 1.10),              # ±10% jitter on packets
                float(max(0, bf + np.random.randint(-1, 2))),    # ±1 jitter on failed connections
                float(bport),                                    # Port stays exact
                float(max(1, bips + np.random.randint(0, 2)))    # +1 jitter on unique IPs
            ])
        return rows

    def _fit(self):
        """
        Executes the actual training phase of the IsolationForest using the
        currently accumulated training_history, and calculates baseline statistics 
        (mean and std) for z-score calculations.
        """
        # Convert historical list to numpy array for sklearn compatibility
        X = np.array(self.training_history, dtype=float)
        
        # Normalize the feature array
        Xs = self.scaler.fit_transform(X)
        
        # Train the Isolation Forest model
        self.model.fit(Xs)
        self.is_trained = True
        
        # Compute the baseline statistical properties of the training data
        self.feature_means = np.mean(X, axis=0)
        self.feature_stds  = np.std(X,  axis=0)
        
        # Edge-case safety: If a feature never changes during training (e.g. port is 
        # always 443), its standard deviation will be 0. We artificially set it to 1.0 
        # to prevent divide-by-zero errors during subsequent z-score calculations.
        self.feature_stds  = np.where(self.feature_stds < 0.01, 1.0, self.feature_stds)

    def _preload_and_train(self):
        """
        Wrapper to populate the initial baseline history and immediately trigger 
        the first fitting phase upon device model instantiation.
        """
        self.training_history = self._generate_baseline()
        self._fit()

    def _count_deviating(self, packets, failed, port, ips):
        """
        Evaluates an individual incoming telemetry row against the trained statistical
        mean and standard deviation. Returns how many, and which, individual features 
        are currently 'deviating' significantly.
        """
        current = np.array([float(packets), float(failed), float(port), float(ips)])
        
        # Calculate the absolute z-score (how many standard deviations away from the mean)
        z = np.abs((current - self.feature_means) / self.feature_stds)
        names = ['packets', 'failed', 'port', 'ips']
        
        # A parameter is considered deviating if its z-score exceeds PARAM_Z_THRESHOLD
        deviating = [n for n, zi in zip(names, z) if zi > PARAM_Z_THRESHOLD]
        return len(deviating), deviating

    def get_score(self, packets, failed, port, ips):
        """
        Main scoring function. Returns an anomaly score mapped from 0.0 (normal) 
        to 1.0 (extreme anomaly).
        """
        if not self.is_trained:
            return 0.0
            
        # 1. Enforce MULTI-PARAMETER constraint: Check how many features deviate significantly.
        # If fewer than MIN_DEVIATING_PARAMS (e.g., 2) have spiked, ignore the event 
        # entirely and return 0.0 (normal). This prevents false positives.
        n_dev, _ = self._count_deviating(packets, failed, port, ips)
        if n_dev < MIN_DEVIATING_PARAMS:
            return 0.0
            
        current = np.array([[float(packets), float(failed), float(port), float(ips)]])
        
        # Scale the incoming new row using the pre-fitted scaler
        try:
            cs = self.scaler.transform(current)
        except Exception:
            # Failsafe: if transformation fails (e.g., NaN values), return benign score
            return 0.0
            
        # Get raw anomaly score from Isolation Forest. 
        # Note: lower decision_function scores indicate MORE anomalous data.
        raw = self.model.decision_function(cs)[0]
        
        # Gather baseline scores to establish normal 'bounds' for this model
        Xt  = self.scaler.transform(np.array(self.training_history, dtype=float))
        ts  = self.model.decision_function(Xt)
        
        # Normalize the raw score to a 0.0-1.0 scale
        rng = max(float(ts.max()) - float(ts.min()), 0.05)
        # (max_normal_score - raw_current_score) / range
        return round(max(0.0, min(1.0, (float(ts.max()) - raw) / rng)), 3)


def _get(device_id):
    """
    Helper function to retrieve a device's specific ML model from the cache,
    or instantiate one if it doesn't exist.
    """
    if device_id not in _device_models:
        _device_models[device_id] = DeviceMLModel(device_id)
    return _device_models[device_id]


def train_model(training_data, device_id='unknown'):
    """
    Ingests live telemetry data continuously to update the model. Maintains
    a growing training history and periodically re-fits the Isolation Forest.
    """
    model = _get(device_id)
    
    # Append new valid rows to the training history
    for row in training_data:
        if len(row) >= 4:
            # Row structure is expected to be [packets, failed, unique_ips, port] however 
            # we rearrange into the internal order: [packets, failed, port, ips] 
            model.training_history.append([float(row[0]), float(row[1]),
                                            float(row[3]), float(row[2])])
                                            
    # Periodically re-fit the model to allow it to gradually adapt to new normals.
    # We trigger a re-fit every 10 new data points.
    if len(model.training_history) % 10 == 0:
        model._fit()
    return True


def get_anomaly_score(packets, failed_connections, unique_ips, port_used, device_id='unknown'):
    """
    Utility wrapper to fetch the normalized anomaly score (0.0 - 1.0)
    for a specific data point.
    """
    return _get(device_id).get_score(packets, failed_connections, port_used, unique_ips)


def check_ml_anomaly(packets, failed_connections, unique_ips, port_used, device_id='unknown'):
    """
    The main integration endpoint called by the processing pipeline. 
    It evaluates the row, calculates the anomaly score, determines if a penalty 
    should be applied, and generates human-readable explanation strings.
    
    Returns:
        penalty (int): The amount to deduct from the Trust Score.
        score (float): The calculated anomaly score (0.0 to 1.0).
        reasons (list): Explanation strings for the dashboard.
    """
    score   = get_anomaly_score(packets, failed_connections, unique_ips, port_used, device_id)
    penalty = 0
    reasons = []
    
    # Evaluate score against threshold tiers to map to Trust Score penalty points
    if score > ML_THRESHOLD:
        # Severe anomaly detected across multiple dimensions
        penalty = 15
        reasons.append(
            f"ML anomaly model (Isolation Forest) flagged HIGH multi-parameter anomaly: "
            f"score {score:.2f}/1.0. Multiple behavioral dimensions deviating "
            f"simultaneously — packets={packets}, failed={failed_connections}, "
            f"port={port_used}. Pattern suggests coordinated compromise."
        )
    elif score > ML_MODERATE_THRESHOLD:
        # Moderate anomaly detected
        penalty = 3
        reasons.append(
            f"ML model detected MODERATE multi-parameter anomaly: "
            f"score {score:.2f}/1.0. Unusual combination of signals detected."
        )
    else:
        # Behavior normal
        reasons.append(f"ML score {score:.2f}/1.0 — behavior consistent with baseline.")
        
    return penalty, score, reasons