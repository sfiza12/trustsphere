import json
import logging
import pandas as pd
import threading
import paho.mqtt.client as mqtt

BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "trustsphere/telemetry"

def start_mqtt_listener(process_telemetry_fn):
    """
    Spawns a background daemon thread that connects to the MQTT broker
    and continuously listens for incoming telemetry data without blocking Flask.
    """
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"Successfully connected to MQTT broker at {BROKER}:{PORT}")
            client.subscribe(TOPIC)
        else:
            logging.error(f"Failed to connect to MQTT broker, return code {rc}")

    def on_message(client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode('utf-8'))
            
            # Map standard payload to pandas DataFrame
            row_data = {
                'device_id': [payload.get('device_id')],
                'timestamp': [payload.get('timestamp')],
                'packets_per_min': [payload.get('packets_per_min')],
                'port_used': [payload.get('port_used')],
                'destination_ip': [payload.get('destination_ip')],
                'failed_connections': [payload.get('failed_connections')]
            }
            
            df = pd.DataFrame(row_data)
            
            # Flow dataframe into the primary orchestration core
            process_telemetry_fn(df)
            
        except Exception as e:
            logging.error(f"Error processing MQTT message: {e}")

    def loop_in_thread():
        client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message

        try:
            client.connect(BROKER, PORT, 60)
            client.loop_forever()
        except Exception as e:
            logging.error(f"MQTT connection forcefully refused or unavailable: {e}")
            # Fails gracefully without taking down the core Flask process.

    # Launch daemon thread
    thread = threading.Thread(target=loop_in_thread, daemon=True)
    thread.start()
