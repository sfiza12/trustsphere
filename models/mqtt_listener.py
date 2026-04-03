import paho.mqtt.client as mqtt  # type: ignore
import json
import pandas as pd  # type: ignore
import logging
from config import MQTT_BROKER, MQTT_PORT, MQTT_TOPIC  # type: ignore

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logging.info(f"Connected to MQTT broker at {MQTT_BROKER}")
        client.subscribe(MQTT_TOPIC)
    else:
        logging.error(f"Failed to connect to MQTT broker, return code {rc}")

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode('utf-8')
        data = json.loads(payload)
        
        if not isinstance(data, list):
            data = [data]
            
        df = pd.DataFrame(data)
        
        # Execute the main orchestrator callback securely
        if 'callback' in userdata:
            userdata['callback'](df)
            
    except Exception as e:
        logging.error(f"Error processing MQTT message: {e}")

def start_mqtt_listener(telemetry_callback):
    """
    Initializes and starts the background MQTT loop.
    Connects to the broker defined in config and routes new messages directly into the pipeline.
    """
    client = mqtt.Client(userdata={'callback': telemetry_callback})
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        # loop_start() handles reconnection and network traffic in a background thread implicitly
        client.loop_start()
        logging.info("MQTT Listener started successfully.")
        return client
    except Exception as e:
        logging.error(f"Failed to start MQTT listener: {e}")
        return None
