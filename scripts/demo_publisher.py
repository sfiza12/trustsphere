import time
import json
import random
import paho.mqtt.client as mqtt

# Pointing to the Global System Defaults
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
MQTT_TOPIC = "trustsphere/telemetry"

device_ids = ["SENSOR_01", "THERMOSTAT_02", "CAM_03", "ROUTER_05"]

client = mqtt.Client()
client.connect(MQTT_BROKER, MQTT_PORT, 60)

print(f"🚀 Connected to {MQTT_BROKER}.")
print("📡 Beginning TrustSphere Live IoT Simulation...")

try:
    while True:
        # 10% chance inherently mapped on the random number generator to 
        # simulate a catastrophic internal DDoS spread attack.
        attack = random.random() > 0.90
        
        device = random.choice(device_ids)
        
        if attack:
            print(f"⚠️ !!! TRIGGERING ANOMALY ON {device} !!! ⚠️")
            payload = {
                "device_id": device,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "packets_per_min": random.randint(5000, 10000),
                "failed_connections": random.randint(50, 900),
                "unique_ips": random.randint(100, 500),
                "port_used": 22
            }
        else:
            payload = {
                "device_id": device,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "packets_per_min": random.randint(10, 150),
                "failed_connections": random.randint(0, 2),
                "unique_ips": random.randint(1, 5),
                "port_used": random.choice([80, 443])
            }
            
        client.publish(MQTT_TOPIC, json.dumps(payload))
        print(f"[*] Published heartbeat: {payload['device_id']}")
        
        # Throttles the loop gracefully
        time.sleep(1.5)
        
except KeyboardInterrupt:
    print("\n🛑 Simulation Terminated Gracefully.")
    client.disconnect()
