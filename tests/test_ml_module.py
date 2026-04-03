import pytest
from models.ml_module import DeviceMLModel

def test_ml_anomaly_detection():
    # Arrange: Initialize model and feed it a perfectly static pattern
    model = DeviceMLModel("SENSOR_01")
    
    # Train it on perfectly normal behavior geometrically (packets, failed, ips, port)
    normal_row = [50.0, 0.0, 2.0, 80.0]
    for _ in range(200):
        model.training_history.append(normal_row)
        
    model._fit_model()
    
    # Act: Feed it heavily anomalous data acting like a compromised asset
    anomaly_payload = {
        'packets_per_min': 5000, 
        'failed_connections': 50, 
        'unique_ips': 200, 
        'port_used': 9999
    }
    
    penalty, is_anomaly = model.evaluate(anomaly_payload)
    
    # Assert
    assert is_anomaly is True, "The IsolationForest ML Model completely failed to map the mathematical anomaly."
    assert penalty > 0, "Expected a generated mathematical penalty."

def test_ml_normal_behavior():
    # Arrange
    model = DeviceMLModel("SENSOR_01")
    normal_row = [50.0, 0.0, 2.0, 80.0]
    for _ in range(200):
        model.training_history.append(normal_row)
    model._fit_model()
    
    # Act: Normal payload matching exactly the baseline shapes
    normal_payload = {
        'packets_per_min': 51, 
        'failed_connections': 0, 
        'unique_ips': 2, 
        'port_used': 80
    }
    
    penalty, is_anomaly = model.evaluate(normal_payload)
    
    # Assert
    assert is_anomaly is False, "The ML model falsely flagged a completely normal behavior as anomalous."
    assert penalty == 0, "Normal behaviors should not incur geometric ML penalties."
