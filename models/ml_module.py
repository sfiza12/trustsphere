# =============================================================================
# ML ANOMALY MODULE — TrustSphere
# =============================================================================
# This module implements an unsupervised Machine Learning anomaly detection engine.
# It uses the Isolation Forest algorithm to establish a behavioral baseline for 
# each unique device and flags structural deviations. 
# 
# KEY DESIGN PRINCIPLE:
# Evaluates MULTI-PARAMETER anomalies only. Instead of penalizing a device solely 
# because its traffic spiked (which the Drift engine already handles), the ML 
# engine looks for coordinated changes across multiple dimensions (e.g. fewer packets 
# but suddenly targeting multiple IPs on a weird port). This significantly reduces 
# false positives and isolates true compromises (like botnet recruitment).
# =============================================================================

import sys
import os
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Import centralized configuration
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import (
    ML_THRESHOLD, 
    ML_MODERATE_THRESHOLD, 
    MIN_DEVIATING_PARAMS, 
    PARAM_Z_THRESHOLD, 
    DEVICE_BASELINES
)

# In-memory cache holding trained models per device
_device_models = {}

class DeviceMLModel:
    """
    Encapsulates the ML state for an individual IoT device.
    Maintains localized training history and statistical normalization tools.
    """
    def __init__(self, device_id):
        self.device_id = device_id
        
        # We use StandardScaler because raw dimensions vary wildly.
        # Packets might be 500 while failed_connections is 2. The Forest would 
        # naturally prioritize the larger numbers without standardization.
        self.scaler = StandardScaler()
        
        # The Isolation Forest isolates outliers by randomly partitioning data.
        # Normal data points require more partitions to be isolated; outliers 
        # require fewer. We assume ~5% of traffic is noisy/outlying natively.
        self.model = IsolationForest(
            n_estimators=100, 
            contamination=0.05, 
            random_state=42
        )
        
        self.is_trained = False
        self.training_history = []
        
        self.feature_means = None
        self.feature_stds = None
        
        # Prepare the model with initial data immediately upon creation so it never
        # crashes when evaluated on the very first row.
        self._preload_and_train()

    def _generate_baseline(self):
        """
        Creates synthetic warm-up data based on hardcoded baseline archetypes.
        Gives the model a "ground truth" to measure against before sufficient 
        live data is accumulated.
        """
        try:
            if self.device_id in DEVICE_BASELINES:
                bp, bf, bport, bips = DEVICE_BASELINES[self.device_id]
            else:
                bp, bf, bport, bips = 50, 5, 443, 2
                
            np.random.seed(42)
            rows = []
            for _ in range(30):
                # Add organic jitter to prevent the model from overfitting to pure static constants
                rows.append([
                    bp * np.random.uniform(0.90, 1.10),
                    float(max(0, bf + np.random.randint(-1, 2))),
                    float(bport),
                    float(max(1, bips + np.random.randint(0, 2)))
                ])
            return rows
        except Exception as e:
            logging.error(f"Error generating baseline for {self.device_id}: {e}")
            return []

    def _fit(self):
        """
        Trains the Isolation Forest and computes statistical means for fallback verification.
        """
        try:
            if len(self.training_history) < 10:
                return # Insufficient data to train

            X = np.array(self.training_history, dtype=float)
            
            # Normalize the array
            X_scaled = self.scaler.fit_transform(X)
            
            # Train model
            self.model.fit(X_scaled)
            self.is_trained = True
            
            # Compute baseline logic for Z-Scores
            self.feature_means = np.mean(X, axis=0)
            self.feature_stds = np.std(X, axis=0)
            
            # Prevent divide by zero error if a feature never changed during training
            self.feature_stds = np.where(self.feature_stds < 0.01, 1.0, self.feature_stds)
            
        except Exception as e:
            logging.error(f"Model fit failed for {self.device_id}: {e}")
            self.is_trained = False

    def _preload_and_train(self):
        """Helper to orchestrate initial seed generation and immediate training."""
        self.training_history = self._generate_baseline()
        self._fit()

    def _count_deviating(self, packets, failed, port, ips):
        """
        Calculates how many individual dimensions are statistically abnormal.
        Used to enforce the MIN_DEVIATING_PARAMS rule.
        """
        try:
            current = np.array([float(packets), float(failed), float(port), float(ips)])
            
            # Absolute z-score evaluates how many standard deviations away from the mean we are
            z = np.abs((current - self.feature_means) / self.feature_stds)
            names = ['packets', 'failed', 'port', 'ips']
            
            deviating = [n for n, zi in zip(names, z) if zi > PARAM_Z_THRESHOLD]
            return len(deviating), deviating
        except Exception as e:
            logging.error(f"Error counting deviation: {e}")
            return 0, []

    def get_score(self, packets, failed, port, ips):
        """
        Evaluates a live row against the Isolation Forest and returns a normalized anomaly score.
        """
        if not self.is_trained:
            return 0.0
            
        try:
            # Enforce multi-parameter constraint
            n_dev, _ = self._count_deviating(packets, failed, port, ips)
            if n_dev < MIN_DEVIATING_PARAMS:
                return 0.0
                
            current = np.array([[float(packets), float(failed), float(port), float(ips)]])
            
            # Scale input against learned history
            current_scaled = self.scaler.transform(current)
            
            # Retrieve raw anomaly decision score (lower is more anomalous)
            raw = self.model.decision_function(current_scaled)[0]
            
            # Determine threshold mapping by comparing raw score against all known training data scores
            X_train_scaled = self.scaler.transform(np.array(self.training_history, dtype=float))
            train_scores = self.model.decision_function(X_train_scaled)
            
            # Normalize to 0.0 -> 1.0 scale mapping
            rng = max(float(train_scores.max()) - float(train_scores.min()), 0.05)
            normalized_score = max(0.0, min(1.0, (float(train_scores.max()) - raw) / rng))
            
            return round(normalized_score, 3)
            
        except Exception as e:
            logging.error(f"Prediction parsing error for {self.device_id}: {e}")
            return 0.0

def _get_model(device_id):
    """Singleton getter for memory caching."""
    if device_id not in _device_models:
        _device_models[device_id] = DeviceMLModel(device_id)
    return _device_models[device_id]

def train_model(training_data, device_id='unknown'):
    """
    Ingests continuous live telemetry to recursively update the model over time.
    Re-fits every 10 data points.
    """
    try:
        model = _get_model(device_id)
        for row in training_data:
            if len(row) >= 4:
                # Row format is presumed as [packets, failed, unique_ips, port]
                # Re-mapped internally to [packets, failed, port, ips] for logical array
                model.training_history.append([
                    float(row[0]), 
                    float(row[1]),
                    float(row[3]), 
                    float(row[2])
                ])
                
        # Adapt model dynamically
        if len(model.training_history) % 10 == 0:
            model._fit()
            
        return True
    except Exception as e:
        logging.error(f"Error passing batch training data for {device_id}: {e}")
        return False

def check_ml_anomaly(packets, failed_connections, unique_ips, port_used, device_id='unknown'):
    """
    Primary API point for the Pipeline Orchestrator. Evaluates the ML score 
    and applies corresponding Trust Score penalties based on configuration limits. 
    """
    score = _get_model(device_id).get_score(packets, failed_connections, port_used, unique_ips)
    penalty = 0
    reasons = []
    
    try:
        if score > ML_THRESHOLD:
            penalty = 15
            reasons.append(
                f"ML anomaly model (Isolation Forest) flagged HIGH multi-parameter anomaly: "
                f"score {score:.2f}/1.0. Multiple behavioral dimensions deviating "
                f"simultaneously — packets={packets}, failed={failed_connections}, "
                f"port={port_used}. Pattern suggests coordinated compromise."
            )
        elif score > ML_MODERATE_THRESHOLD:
            penalty = 3
            reasons.append(
                f"ML model detected MODERATE multi-parameter anomaly: "
                f"score {score:.2f}/1.0. Unusual combination of signals detected."
            )
        else:
            reasons.append(f"ML score {score:.2f}/1.0 — behavior consistent with baseline.")
            
    except Exception as e:
        logging.error(f"Error finalizing ML evaluation: {e}")
        score = 0.0
        
    return penalty, score, reasons