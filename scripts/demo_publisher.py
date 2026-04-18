"""
demo_publisher.py

What this script does:
This script simulates 5 specific IoT devices and publishes realistic telemetry 
data to TrustSphere's MQTT topic. The simulation runs across 4 sequential 
scenarios (Normal, Drift Begins, Escalation, Resolution) to dynamically trigger 
different engines inside the TrustSphere backend, allowing you to see how the 
platform catches drifting behavior and isolated attack anomalies in real-time.

How to run it:
python scripts/demo_publisher.py

What to watch on the TrustSphere dashboard:
1. Watch the primary dashboard slowly shift the THERMOSTAT_02 score down as it drifts.
2. Watch ROUTER_05 get an immediate critical hard violation for using port 6667.
3. Watch the ML Anomaly forest detect BULB_04 combining high failing connection attempts.
"""

import time
import json
import random
import datetime
import threading
import paho.mqtt.client as mqtt

BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "trustsphere/telemetry"

devices = {
    "SENSOR_01": {"base": 20, "port": 443, "ip": "192.168.1.10", "failed": 1},
    "THERMOSTAT_02": {"base": 50, "port": 443, "ip": "192.168.1.20", "failed": 2},
    "CAM_03": {"base": 100, "port": 443, "ip": "192.168.1.30", "failed": 2},
    "BULB_04": {"base": 5, "port": 443, "ip": "192.168.1.40", "failed": 0},
    "ROUTER_05": {"base": 150, "port": 443, "ip": "192.168.1.50", "failed": 4}
}

def connect_mqtt():
    try:
        # Use Callback API version 2 to prevent deprecation warnings if supported
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        except AttributeError:
            client = mqtt.Client()
            
        client.connect(BROKER, PORT, 60)
        return client
    except Exception as e:
        print(f"\n[!] ERROR: Cannot connect to MQTT Broker at {BROKER}:{PORT}")
        print(f"Details: {e}")
        print("Exiting gracefully...\n")
        import sys
        sys.exit(1)

def get_base(d_id, key):
    return devices[d_id][key]

def apply_noise(base_val):
    """Applies a tiny +-10% random noise to make numbers realistic."""
    noise_range = int(base_val * 0.10)
    if noise_range == 0:
        noise_range = 1
    return base_val + random.randint(-noise_range, noise_range)

def publish_event(client, d_id, pkt, port, ip, failed):
    time_str = datetime.datetime.now().isoformat() + "Z"
    
    payload = {
        "device_id": d_id,
        "timestamp": time_str,
        "packets_per_min": pkt,
        "port_used": port,
        "destination_ip": ip,
        "failed_connections": failed
    }
    
    client.publish(TOPIC, json.dumps(payload))
    terminal_time = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{terminal_time}] {d_id.ljust(13)} → port={port} ip={ip.ljust(14)} failed={failed} pkt={pkt}")

def process_iteration(client, overrides=None):
    if overrides is None:
        overrides = {}
        
    for device_id in devices.keys():
        if device_id in overrides:
            pkt, port, ip, failed = overrides[device_id]
            publish_event(client, device_id, pkt, port, ip, failed)
        else:
            # Baseline normal path
            pkt = apply_noise(get_base(device_id, "base"))
            publish_event(client, device_id, pkt, get_base(device_id, "port"), 
                          get_base(device_id, "ip"), get_base(device_id, "failed"))

def main():
    print("Initializing TrustSphere Demo Publisher...")
    client = connect_mqtt()
    print(f"✅ Connected seamlessly to {BROKER}:{PORT}")
    print("\nStarting the 4-stage IoT Network Simulation!\n")
    
    # ---------------------------------------------------------
    # SCENARIO 1 — Normal (6 iterations)
    # ---------------------------------------------------------
    print("==================================================")
    print(" SCENARIO 1: NORMAL BASELINE (All clean data)")
    print("==================================================")
    for _ in range(6):
        process_iteration(client)
        time.sleep(5)
        
    # ---------------------------------------------------------
    # SCENARIO 2 — Drift begins (6 iterations)
    # ---------------------------------------------------------
    print("\n==================================================")
    print(" SCENARIO 2: ANOMALY DRIFT BEGINS")
    print("==================================================")
    bulb_fails = [10, 14, 18, 22, 26, 30]
    for i in range(6):
        ov = {
            "THERMOSTAT_02": (random.randint(68, 73), 443, get_base("THERMOSTAT_02", "ip"), get_base("THERMOSTAT_02", "failed")),
            "ROUTER_05": (apply_noise(150), 6667, "185.99.12.34", 60),
            "BULB_04": (apply_noise(5), random.choice([443, 8080]), get_base("BULB_04", "ip"), bulb_fails[i])
        }
        process_iteration(client, ov)
        time.sleep(5)
        
    # ---------------------------------------------------------
    # SCENARIO 3 — Escalation (6 iterations)
    # ---------------------------------------------------------
    print("\n==================================================")
    print(" SCENARIO 3: ESCALATION (Threat compounding)")
    print("==================================================")
    for i in range(6):
        ov = {
            "THERMOSTAT_02": (random.randint(66, 71), 443, get_base("THERMOSTAT_02", "ip"), get_base("THERMOSTAT_02", "failed")),
            "ROUTER_05": (apply_noise(150), 6667, "185.99.12.34", 60),
            "BULB_04": (apply_noise(5), 8080, get_base("BULB_04", "ip"), random.randint(32, 42))
        }
        process_iteration(client, ov)
        time.sleep(5)
        
    # ---------------------------------------------------------
    # SCENARIO 4 — Resolution (6 iterations)
    # ---------------------------------------------------------
    print("\n==================================================")
    print(" SCENARIO 4: RESOLUTION AND ADAPTATION")
    print("==================================================")
    for i in range(6):
        ov = {
            "THERMOSTAT_02": (random.randint(64, 66), 443, get_base("THERMOSTAT_02", "ip"), get_base("THERMOSTAT_02", "failed")),
            "ROUTER_05": (apply_noise(150), 6667, "185.99.12.34", 60),
            "BULB_04": (apply_noise(5), random.choice([443, 8080]), get_base("BULB_04", "ip"), random.randint(43, 48))
        }
        process_iteration(client, ov)
        time.sleep(5)
        
    print("\n🏁 Simulation complete. Gracefully terminating Publisher.")
    client.disconnect()

if __name__ == "__main__":
    main()
