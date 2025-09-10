import os
import sys
import joblib
import numpy as np
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import importlib.util
import tensorflow as tf
from tensorflow import keras
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timedelta
from pymongo import MongoClient
from app.report import router as report_router
from app.auth import router as auth_router
from app.geomap import router as geomap_router, record_threat_location
from app.pcap_analyzer import router as pcap_router
from app.alert_system import router as alert_router, process_detection_for_alerts

import threading
import time
from scapy.all import get_if_list, sniff
import platform
import subprocess
import re

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import numpy as np
import pandas as pd
import joblib
import subprocess
import requests
from pymongo import MongoClient
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import timezone utilities
from app.timezone_utils import get_beijing_time, get_beijing_time_iso

# Load .env very early
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# Add CORS middleware (credentials + specific origins)
cors_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in cors_origins if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Add lifespan event handlers
@app.on_event("startup")
async def startup_event():
    """Application startup initialization"""
    print("🚀 PreTech NIDS application starting...")
    load_thresholds()
    print("✅ Application startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown cleanup"""
    print("🛑 PreTech NIDS application shutting down...")
    global real_time_detector, is_capturing
    
    # Stop real-time detection
    if is_capturing and real_time_detector:
        try:
            real_time_detector.stop_capture()
            print("✅ Real-time detection stopped")
        except Exception as e:
            print(f"⚠️ Error stopping real-time detection: {e}")
    
    # Close database connection
    try:
        client.close()
        print("✅ Database connection closed")
    except Exception as e:
        print(f"⚠️ Error closing database connection: {e}")
    
    print("✅ Application shutdown complete")

app.include_router(report_router)
app.include_router(auth_router, prefix="/auth", tags=["authentication"])
app.include_router(geomap_router, prefix="/api/geomap", tags=["geomap"])
app.include_router(pcap_router, prefix="/api/pcap", tags=["pcap"])
app.include_router(alert_router, prefix="/api/alerts", tags=["alerts"])


# Add static file serving for uploads (use absolute path to avoid CWD issues)
static_dir = Path(__file__).resolve().parent.parent / "uploads"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# ---------- MongoDB ----------
# Prefer environment variable for cloud deployments (e.g., Render/MongoDB Atlas)
# For local development, you can use MongoDB Atlas or local MongoDB
# To use MongoDB Atlas: Set MONGODB_URI environment variable to your Atlas connection string
# Example: mongodb+srv://username:password@cluster.mongodb.net/PreTectNIDS
client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client['PreTectNIDS']
reports = db['detection_reports']

# ---------- Real-time detection state ----------
real_time_detector = None
capture_thread = None
is_capturing = False
current_interface = None
current_model = None
current_use_all_models = None

# ---------- Get available network interfaces ----------
def get_windows_interfaces_precise():
    try:
        # 1. Get GUID, description, friendly name
        print("🔍 Getting Windows network interfaces...")
        output = subprocess.check_output('wmic nic get GUID,Name,NetConnectionID', shell=True, encoding='gbk', errors='ignore')
        lines = output.splitlines()
        guid_map = {}
        for line in lines:
            parts = [p.strip() for p in line.split('  ') if p.strip()]
            if len(parts) == 3:
                guid, desc, netid = parts
                guid = guid.replace('{','').replace('}','').upper()
                if netid:
                    guid_map[guid] = {'desc': desc, 'netid': netid}
        
        print(f"✅ Found {len(guid_map)} network adapters")
        
        # 2. Map scapy interface ID to GUID
        from scapy.all import get_if_list
        interfaces = get_if_list()
        print(f"✅ Scapy found {len(interfaces)} interfaces")
        
        friendly_interfaces = []
        for iface in interfaces:
            # Handle different interface name formats
            if iface.startswith('\\Device\\NPF_'):
                # Already in correct format
                guid = iface.split('_')[-1].replace('{','').replace('}','').upper()
                info = guid_map.get(guid)
                if info:
                    display = f'{info["netid"]} ({info["desc"]}) ({guid[-8:]})'
                else:
                    display = f'Unknown ({guid[-8:]})'
                friendly_interfaces.append({'name': iface, 'display': display})
            elif iface.startswith('{') and iface.endswith('}'):
                # Convert GUID format to NPF format
                guid = iface.replace('{','').replace('}','').upper()
                npf_name = f'\\Device\\NPF_{{{guid}}}'
                info = guid_map.get(guid)
                if info:
                    display = f'{info["netid"]} ({info["desc"]}) ({guid[-8:]})'
                else:
                    display = f'Unknown ({guid[-8:]})'
                friendly_interfaces.append({'name': npf_name, 'display': display})
            else:
                # Other formats (like loopback)
                friendly_interfaces.append({'name': iface, 'display': iface})
        
        print(f"✅ Mapped {len(friendly_interfaces)} interfaces")
        return friendly_interfaces
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to execute wmic command: {e}")
        print("Trying fallback method...")
        # Fallback: just return scapy interfaces
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            return [{'name': iface, 'display': iface} for iface in interfaces]
        except Exception as fallback_error:
            print(f"❌ Fallback also failed: {fallback_error}")
            return []
    except Exception as e:
        print(f'❌ Failed to get friendly interface names: {e}')
        return []

def get_available_interfaces():
    if platform.system().lower() == 'windows':
        return get_windows_interfaces_precise()
    else:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        return [{'name': iface, 'display': iface} for iface in interfaces]

def validate_interface(interface_name):
    """Validate if a network interface is available and accessible"""
    try:
        available_interfaces = get_available_interfaces()
        interface_names = [i['name'] for i in available_interfaces]
        
        if interface_name not in interface_names:
            return False, f"Interface '{interface_name}' not found. Available interfaces: {interface_names}"
        
        # Try to resolve the interface
        try:
            from scapy.all import resolve_iface
            resolved_iface = resolve_iface(interface_name)
            return True, f"Interface '{interface_name}' is valid and accessible"
        except Exception as e:
            return False, f"Interface '{interface_name}' cannot be resolved: {str(e)}"
            
    except Exception as e:
        return False, f"Error validating interface: {str(e)}"

# ---------- Model paths ----------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
KITSUNE_MODEL_PATH = os.path.join(MODEL_DIR, "kitsune_model.pkl")
AE_MODEL_PATH = os.path.join(MODEL_DIR, "ae_model.h5")
AE_SCALER_PATH = os.path.join(MODEL_DIR, "ae_scaler.pkl")
LSTM_MODEL_PATH = os.path.join(MODEL_DIR, "lstm_model.h5")
LSTM_SCALER_PATH = os.path.join(MODEL_DIR, "lstm_scaler.pkl")
CNN_MODEL_PATH = os.path.join(MODEL_DIR, "cnn_dnn_model.h5")
CNN_SCALER_PATH = os.path.join(MODEL_DIR, "cnn_dnn_scaler.pkl")
RF_MODEL_PATH = os.path.join(MODEL_DIR, "rf_model.pkl")
RF_SCALER_PATH = os.path.join(MODEL_DIR, "rf_scaler.pkl")

# ---------- Thresholds (will be loaded from files if available) ----------
KITSUNE_THRESHOLD = 0.2  # Default fallback
AE_THRESHOLD = 1.0       # Default fallback  
LSTM_THRESHOLD = 10.0    # Default fallback
CNN_THRESHOLD = 0.5      # Default fallback
RF_THRESHOLD = 0.5       # Default fallback

# Load thresholds from files if available
def load_thresholds():
    global KITSUNE_THRESHOLD, AE_THRESHOLD, LSTM_THRESHOLD, CNN_THRESHOLD, RF_THRESHOLD
    
    # Load Autoencoder threshold
    if os.path.exists("models/ae_threshold.txt"):
        try:
            with open("models/ae_threshold.txt", "r") as f:
                AE_THRESHOLD = float(f.read().strip())
                print(f"✅ Autoencoder threshold loaded: {AE_THRESHOLD}")
        except Exception as e:
            print(f"⚠️ Failed to load AE threshold: {e}")
    
    # Load LSTM threshold
    if os.path.exists("models/lstm_threshold.txt"):
        try:
            with open("models/lstm_threshold.txt", "r") as f:
                LSTM_THRESHOLD = float(f.read().strip())
                print(f"✅ LSTM threshold loaded: {LSTM_THRESHOLD}")
        except Exception as e:
            print(f"⚠️ Failed to load LSTM threshold: {e}")
    
    # Load CNN-DNN threshold
    if os.path.exists("models/cnn_dnn_threshold.txt"):
        try:
            with open("models/cnn_dnn_threshold.txt", "r") as f:
                CNN_THRESHOLD = float(f.read().strip())
                print(f"✅ CNN-DNN threshold loaded: {CNN_THRESHOLD}")
        except Exception as e:
            print(f"⚠️ Failed to load CNN threshold: {e}")
    
    # Load Random Forest threshold
    if os.path.exists("models/rf_threshold.txt"):
        try:
            with open("models/rf_threshold.txt", "r") as f:
                RF_THRESHOLD = float(f.read().strip())
                print(f"✅ Random Forest threshold loaded: {RF_THRESHOLD}")
        except Exception as e:
            print(f"⚠️ Failed to load RF threshold: {e}")
    
    # Load Kitsune threshold (produced by training/evaluation pipeline)
    if os.path.exists("models/kitsune_threshold.txt"):
        try:
            with open("models/kitsune_threshold.txt", "r") as f:
                KITSUNE_THRESHOLD = float(f.read().strip())
                print(f"✅ Kitsune threshold loaded: {KITSUNE_THRESHOLD}")
        except Exception as e:
            print(f"⚠️ Failed to load Kitsune threshold: {e}")

# Load thresholds on startup
load_thresholds()

# ---------- Kitsune loading ----------
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "kitsune"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "kitsune", "KitNET"))
da_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "kitsune", "KitNET", "dA.py"))
spec = importlib.util.spec_from_file_location("KitNET.dA", da_path)
if spec is not None:
    da_module = importlib.util.module_from_spec(spec)
    sys.modules["KitNET.dA"] = da_module
    if spec.loader is not None:
        spec.loader.exec_module(da_module)

try:
    kitsune_model = joblib.load(KITSUNE_MODEL_PATH)
    print("✅ Kitsune model loaded successfully")
except Exception as e:
    print(f"⚠️ Failed to load Kitsune model: {e}")
    kitsune_model = None

# ---------- Load other models ----------
try:
    ae_model = keras.models.load_model(AE_MODEL_PATH)
    ae_scaler = joblib.load(AE_SCALER_PATH)
    print("✅ Autoencoder model loaded successfully")
except Exception as e:
    print(f"⚠️ Failed to load Autoencoder model: {e}")
    ae_model = None
    ae_scaler = None

try:
    lstm_model = keras.models.load_model(LSTM_MODEL_PATH)
    lstm_scaler = joblib.load(LSTM_SCALER_PATH)
    print("✅ LSTM model loaded successfully")
except Exception as e:
    print(f"⚠️ Failed to load LSTM model: {e}")
    lstm_model = None
    lstm_scaler = None

try:
    cnn_model = keras.models.load_model(CNN_MODEL_PATH)
    cnn_scaler = joblib.load(CNN_SCALER_PATH)
    print("✅ CNN-DNN model loaded successfully")
except Exception as e:
    print(f"⚠️ Failed to load CNN-DNN model: {e}")
    cnn_model = None
    cnn_scaler = None

try:
    rf_model = joblib.load(RF_MODEL_PATH)
    rf_scaler = joblib.load(RF_SCALER_PATH)
    print("✅ Random Forest model loaded successfully")
    # Log model info for debugging
    if hasattr(rf_model, 'feature_names_in_'):
        print(f"Random Forest model has {len(rf_model.feature_names_in_)} feature names")
    else:
        print("Random Forest model has no feature names")
except Exception as e:
    print(f"⚠️ Failed to load Random Forest model: {e}")
    rf_model = None
    rf_scaler = None

# ---------- CORS settings ----------
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:5173", "http://localhost:5174", "http://127.0.0.1:5173", "http://127.0.0.1:5174"],  # Specific origins
#     allow_credentials=True,
#     allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
#     allow_headers=["*"],
#     expose_headers=["*"],
#     max_age=3600,  # Cache preflight requests for 1 hour
# )

# ---------- Request body structure ----------
class FeatureInput(BaseModel):
    features: list[float]
    model: str

# ---------- Root path ----------
@app.get("/")
def root():
    return {"message": "✅ PreTect-NIDS API is running"}

# ---------- Get network interfaces ----------
@app.get("/interfaces")
def get_interfaces():
    interfaces = get_available_interfaces()
    return {"interfaces": interfaces}

# ---------- Dashboard endpoints ----------
@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get total alerts count
        total_alerts = reports.count_documents({"type": {"$in": ["manual_testing", "real_time_detection"]}})
        
        # Get recent attacks (last 24 hours)
        yesterday = get_beijing_time() - timedelta(hours=24)
        recent_attacks = reports.count_documents({
            "type": {"$in": ["manual_testing", "real_time_detection"]},
            "result.prediction": "Attack",
            "timestamp": {"$gte": yesterday.isoformat()}
        })
        
        # Check system status
        system_status = "Online"
        
        return {
            "total_alerts": total_alerts,
            "recent_attacks": recent_attacks,
            "system_status": system_status,
            "last_update": get_beijing_time_iso()
        }
    except Exception as e:
        print(f"Dashboard stats error: {e}")
        return {
            "total_alerts": 0,
            "recent_attacks": 0,
            "system_status": "Online",
            "last_update": get_beijing_time_iso()
        }

@app.get("/api/alerts/recent")
async def get_recent_alerts():
    """Get recent alerts for dashboard"""
    try:
        # Get recent detection reports
        recent_reports = list(reports.find(
            {"type": {"$in": ["manual_testing", "real_time_detection"]}},
            {"_id": 0, "timestamp": 1, "result": 1, "type": 1}
        ).sort("timestamp", -1).limit(10))
        
        # Format alerts
        alerts = []
        for report in recent_reports:
            if report.get("result", {}).get("prediction") == "Attack":
                alerts.append({
                    "type": "Security Threat",
                    "severity": "high",
                    "message": f"{report.get('type', 'Unknown')} detected: {report.get('result', {}).get('model', 'Unknown model')}",
                    "timestamp": report.get("timestamp")
                })
        
        return {"alerts": alerts}
    except Exception as e:
        print(f"Recent alerts error: {e}")
        return {"alerts": []}

# ---------- Model prediction logic (shared) ----------
def model_predict(features, model_name):
    """Unified model prediction logic for both API and real-time detection."""
    import numpy as np
    result = {}
    if model_name == "lstm":
        # LSTM classifier expects (1, 10, 77)
        if len(features) == 770:
            features = np.array(features).reshape(1, 10, 77)
        elif len(features) == 77:
            features = np.tile(features, (10, 1)).reshape(1, 10, 77)
        else:
            return {"error": f"LSTM expects 770 (10x77) or 77 features, got {len(features)}"}
        if lstm_model is None or lstm_scaler is None:
            return {"error": "LSTM model not loaded"}
        X = np.array([lstm_scaler.transform(seq) for seq in features])
        prob = lstm_model.predict(X)[0][0]
        prediction = "Attack" if prob >= LSTM_THRESHOLD else "Normal"
        result = {"model": "LSTM", "probability": prob, "prediction": prediction}
    elif model_name == "kitsune":
        if kitsune_model is None:
            return {"error": "Kitsune model not loaded"}
        try:
            arr = np.array(features, dtype=float).flatten()
        except Exception:
            return {"error": f"Invalid features for Kitsune: expected numeric list, got {type(features)}"}
        if arr.size < 100:
            arr = np.pad(arr, (0, 100 - arr.size), mode='constant')
        elif arr.size > 100:
            arr = arr[:100]
        score = kitsune_model.execute(arr)
        prediction = "Attack" if score > KITSUNE_THRESHOLD else "Normal"
        result = {"model": "Kitsune", "anomaly_score": float(score), "prediction": prediction}
    elif model_name == "autoencoder":
        if ae_model is None or ae_scaler is None:
            return {"error": "Autoencoder model not loaded"}
        X = ae_scaler.transform(np.array(features).reshape(1, -1))
        recon = ae_model.predict(X)
        mse = float(np.mean(np.square(X - recon)))
        prediction = "Attack" if mse > AE_THRESHOLD else "Normal"
        result = {"model": "Autoencoder", "anomaly_score": mse, "prediction": prediction}
    elif model_name == "cnn":
        if cnn_model is None or cnn_scaler is None:
            return {"error": "CNN-DNN model not loaded"}
        X = cnn_scaler.transform(np.array(features).reshape(1, -1))
        X = np.expand_dims(X, axis=-1)
        prob = cnn_model.predict(X)[0][0]
        label = int(prob >= CNN_THRESHOLD)
        prediction = "Attack" if label == 1 else "Normal"
        result = {"model": "CNN-DNN", "probability": float(prob), "threshold": CNN_THRESHOLD, "prediction": prediction}
    elif model_name == "rf":
        if rf_model is None or rf_scaler is None:
            return {"error": "Random Forest model not loaded"}
        X = rf_scaler.transform(np.array(features).reshape(1, -1))
        # Handle feature names if model was trained with them
        if hasattr(rf_model, 'feature_names_in_'):
            # Create a DataFrame with feature names to match training
            import pandas as pd
            # Generate feature names that match the training data structure
            feature_names = []
            for i in range(len(features)):
                if i < 7:  # TCP/UDP specific features
                    feature_names.append(f'feature_{i}')
                elif i < 11:  # IP layer features
                    feature_names.append(f'ip_feature_{i-7}')
                else:  # Padded features
                    feature_names.append(f'padded_feature_{i-11}')
            
            X_df = pd.DataFrame(X, columns=feature_names)
            label = int(rf_model.predict(X_df)[0])
            prob = float(rf_model.predict_proba(X_df)[0][1])
        else:
            # Use numpy array directly if no feature names
            label = int(rf_model.predict(X)[0])
            prob = float(rf_model.predict_proba(X)[0][1])
        
        # Debug: Log the prediction process
        print(f"🔍 RF Debug - Label: {label}, Type: {type(label)}")
        print(f"🔍 RF Debug - Model classes: {rf_model.classes_ if hasattr(rf_model, 'classes_') else 'No classes'}")
        
        prediction = "Attack" if label == 1 else "Normal"
        print(f"🔍 RF Debug - Final prediction: '{prediction}' (length: {len(prediction)})")
        
        result = {"model": "Random Forest", "probability": prob, "threshold": RF_THRESHOLD, "prediction": prediction}
        print(f"🔍 RF Debug - Result object: {result}")
        
        return result
    else:
        return {"error": f"Model '{model_name}' not supported"}
    return result

# ---------- Predict endpoint ----------
@app.post("/predict")
async def predict(input: FeatureInput, request: Request):
    try:
        # Import here to avoid circular imports
        from app.auth import get_current_user_from_request, has_permission, get_default_role
        # Check permission
        user = await get_current_user_from_request(request)
        if not has_permission(user.get("role", get_default_role()), "manual_testing"):
            raise HTTPException(status_code=403, detail="Permission denied: manual_testing required")
    except HTTPException as e:
        if e.status_code == 403:
            raise e
        # If auth fails, allow access for now (backward compatibility)
        pass
    features = np.array(input.features)
    model_name = input.model.lower()
    try:
        result = model_predict(features, model_name)
        # Save report
        report = {
            "timestamp": get_beijing_time_iso(),
            "model": input.model,
            "features": input.features,
            "result": result,
            "type": "manual_testing"
        }
        reports.insert_one(report)
        # Record threat location if attack detected
        record_threat_location(report)
        # Process for alerts
        process_detection_for_alerts(report)
        return result
    except Exception as e:
        return {"error": f"Prediction error: {str(e)}"}

# ---------- Real-time detection class ----------
class RealTimeDetector:
    def __init__(self, model="kitsune"):
        self.is_capturing = False
        self.packet_count = 0
        self.model = model
        self.models = ['kitsune', 'autoencoder', 'lstm', 'cnn', 'rf']
        self.interface = None  # Store the interface being used
        
    def packet_callback(self, packet):
        from scapy.all import IP, TCP, UDP, ICMP
        meta_info = self.extract_meta_info(packet)
        
        # Enhanced blacklist for common noisy/broadcast/service ports (UDP and TCP)
        # These ports are often used for broadcast, multicast, or background services and are not useful for attack detection
        udp_blacklist = [2200, 137, 138, 1900, 5353, 67, 68, 445, 123, 3702, 5355, 500, 4500, 53, 161, 162, 520, 514, 1812, 1813, 69, 111, 2049, 6000] + list(range(49152, 65536))
        tcp_blacklist = [139, 445]
        
        # Additional blacklist for common Metasploit and penetration testing ports
        # These ports are commonly used during setup and should be filtered to reduce false positives
        metasploit_ports = [4444, 8080, 8180, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090]
        tcp_blacklist.extend(metasploit_ports)
        
        # Additional blacklist for multicast, broadcast, and local-link IPs
        def is_multicast(ip):
            try:
                return ip and ip.startswith('224.') or ip.startswith('239.')
            except:
                return False
        def is_broadcast(ip):
            return ip == '255.255.255.255'
        def is_local_link(ip):
            return ip and ip.startswith('169.254.')
        
        # Enhanced filtering: Filter out blacklisted noisy traffic and irrelevant IPs
        if (meta_info['protocol'] == 'UDP' and meta_info['dst_port'] in udp_blacklist) or \
           (meta_info['protocol'] == 'TCP' and meta_info['dst_port'] in tcp_blacklist) or \
           (meta_info['src_ip'] is None or meta_info['dst_ip'] is None) or \
           is_multicast(meta_info['dst_ip']) or is_broadcast(meta_info['dst_ip']) or is_local_link(meta_info['dst_ip']):
            return
        
        # Additional filtering for LHOST setup activities
        # Filter out common setup and discovery packets that might be generated during LHOST configuration
        if meta_info['protocol'] == 'TCP':
            # Filter out common setup packets (SYN, ACK, RST) with low port numbers
            if meta_info['dst_port'] < 1024 and meta_info['src_ip'] and meta_info['dst_ip']:
                # Skip common setup activities
                return
        
        # Only print for packets that will be processed
        print("Packet summary:", packet.summary())
        print("Meta info:", meta_info)
        
        results = []
        models_to_run = self.models if getattr(self, 'use_all_models', True) else [self.model]
        for model in models_to_run:
            features = self.extract_features(packet, for_model=model)
            if features:
                try:
                    result = model_predict(features, model)
                    results.append(result)
                except Exception as e:
                    print(f"{model} model detection error: {e}")
                    results.append({
                        "model": model,
                        "prediction": "Error",
                        "error": str(e)
                    })
        threats_detected = [r for r in results if r.get('prediction') == 'Attack']
        if threats_detected:
            print(f"🚨 THREAT DETECTED by {len(threats_detected)} model(s):")
            for result in threats_detected:
                print(f"  - {result['model']}: {result}")
            self.save_threat_report(results, features, meta_info)
    
    def extract_features(self, packet, for_model=None):
        from scapy.all import IP, TCP, UDP, ICMP
        # Only process packets with IP layer; silently skip non-IP packets
        if not packet.haslayer(IP):
            return None
        try:
            features = []
            if packet.haslayer(TCP):
                features.extend([
                    float(packet[IP].len),
                    float(packet[TCP].sport),
                    float(packet[TCP].dport),
                    float(int(packet[TCP].flags)),  # Ensure flags is int then float
                    float(packet[TCP].window),
                    float(packet[TCP].seq),
                    float(packet[TCP].ack),
                ])
            elif packet.haslayer(UDP):
                features.extend([
                    float(packet[IP].len),
                    float(packet[UDP].sport),
                    float(packet[UDP].dport),
                    float(packet[UDP].len),
                    0.0, 0.0, 0.0
                ])
            features.extend([
                float(packet[IP].ttl),
                float(packet[IP].id),
                float(packet[IP].frag),
                float(packet[IP].proto),
            ])
            # Pad/cut features for model
            if for_model == 'kitsune':
                while len(features) < 100:
                    features.append(0.0)
                features = features[:100]
            else:
                while len(features) < 77:
                    features.append(0.0)
                features = features[:77]
            return features
        except Exception as e:
            # Optionally, log only in debug mode
            # print(f"Feature extraction error: {e}")
            return None

    def extract_meta_info(self, packet):
        # Extract src_ip, dst_ip, dst_port, protocol from packet
        from scapy.all import IP, TCP, UDP, ICMP
        meta = {
            'src_ip': None,
            'dst_ip': None,
            'dst_port': None,
            'protocol': None
        }
        if packet.haslayer(IP):
            meta['src_ip'] = packet[IP].src
            meta['dst_ip'] = packet[IP].dst
            if packet.haslayer(TCP):
                meta['protocol'] = 'TCP'
                meta['dst_port'] = packet[TCP].dport
            elif packet.haslayer(UDP):
                meta['protocol'] = 'UDP'
                meta['dst_port'] = packet[UDP].dport
            elif packet.haslayer(ICMP):
                meta['protocol'] = 'ICMP'
        return meta
    
    def detect_threat_all_models(self, features):
        results = []
        for model in self.models:
            try:
                # Pad/cut features for each model
                if model == 'kitsune':
                    model_features = features + [0.0] * (100 - len(features)) if len(features) < 100 else features[:100]
                else:
                    model_features = features + [0.0] * (77 - len(features)) if len(features) < 77 else features[:77]
                result = model_predict(model_features, model)
                results.append(result)
            except Exception as e:
                print(f"{model} model detection error: {e}")
                results.append({
                    "model": model,
                    "prediction": "Error",
                    "error": str(e)
                })
        return results
    
    def save_threat_report(self, results, features, meta_info=None):
        try:
            for result in results:
                if result.get('prediction') == 'Attack':
                    report = {
                        "timestamp": get_beijing_time_iso(),
                        "model": result.get('model', 'Unknown'),
                        "features": features,
                        "result": result,
                        "type": "real_time_detection",
                        "interface": self.interface  # Include network interface
                    }
                    # Add meta info if available
                    if meta_info:
                        report.update(meta_info)
                    reports.insert_one(report)
                    print(f"✅ {result.get('model')} threat report saved")
                    # Record threat location
                    record_threat_location(report)
                    # Process for alerts
                    process_detection_for_alerts(report)
            
        except Exception as e:
            print(f"Save report error: {e}")
    
    def start_capture(self, interface="eth0", use_all_models=True):
        self.is_capturing = True
        self.use_all_models = use_all_models
        self.interface = interface  # Store the interface
        
        if use_all_models:
            print(f"🔄 Starting real-time capture on interface {interface} with all models...")
        else:
            print(f"🔄 Starting real-time capture on interface {interface} with model {self.model}...")
        
        try:
            # Windows-specific interface validation
            if platform.system().lower() == 'windows':
                # Check if interface name is valid
                if not interface.startswith('\\Device\\NPF_') and not interface.startswith('{'):
                    print(f"⚠️ Warning: Interface '{interface}' may not be in correct Windows format")
                    print("Expected format: \\Device\\NPF_{GUID} or {GUID}")
                
                # Try to resolve the interface first
                try:
                    from scapy.all import resolve_iface
                    resolved_iface = resolve_iface(interface)
                    print(f"✅ Interface resolved: {resolved_iface.network_name}")
                except Exception as resolve_error:
                    print(f"⚠️ Interface resolution failed: {resolve_error}")
                    print("Available interfaces:")
                    available_interfaces = get_available_interfaces()
                    for i, iface in enumerate(available_interfaces):
                        print(f"  {i+1}. {iface['display']} -> {iface['name']}")
                    raise Exception(f"Invalid interface '{interface}'. Please use one of the available interfaces above.")
            
            # Start packet capture
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda x: not self.is_capturing
            )
        except PermissionError:
            error_msg = "Permission denied. Please run the application as Administrator."
            print(f"❌ {error_msg}")
            raise Exception(error_msg)
        except OSError as e:
            if "123" in str(e) or "syntax is incorrect" in str(e):
                error_msg = f"Interface '{interface}' syntax error. Please check the interface name format."
                print(f"❌ {error_msg}")
                print("Available interfaces:")
                available_interfaces = get_available_interfaces()
                for i, iface in enumerate(available_interfaces):
                    print(f"  {i+1}. {iface['display']} -> {iface['name']}")
                raise Exception(error_msg)
            else:
                print(f"❌ Capture error: {e}")
                raise
        except Exception as e:
            print(f"❌ Capture error: {e}")
            raise
    
    def stop_capture(self):
        self.is_capturing = False
        print("⏹️ Real-time capture stopped")

# ---------- Real-time detection request body ----------
class RealTimeConfig(BaseModel):
    interface: str = "eth0"
    model: str = "kitsune"
    use_all_models: bool = True

# ---------- Interface management endpoints ----------
@app.get("/interfaces")
def get_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = get_available_interfaces()
        return {
            "interfaces": interfaces,
            "count": len(interfaces),
            "platform": platform.system()
        }
    except Exception as e:
        return {"error": f"Failed to get interfaces: {str(e)}"}

@app.get("/interfaces/{interface_name}/validate")
def validate_interface_endpoint(interface_name: str):
    """Validate a specific network interface"""
    try:
        is_valid, message = validate_interface(interface_name)
        return {
            "interface": interface_name,
            "is_valid": is_valid,
            "message": message
        }
    except Exception as e:
        return {"error": f"Validation failed: {str(e)}"}

# ---------- Real-time detection endpoints ----------
@app.post("/start-realtime")
async def start_realtime_detection(config: RealTimeConfig, request: Request):
    try:
        # Import here to avoid circular imports
        from app.auth import get_current_user_from_request, has_permission, get_default_role
        
        # Check permission
        user = await get_current_user_from_request(request)
        if not has_permission(user.get("role", get_default_role()), "real_time_detection"):
            raise HTTPException(status_code=403, detail="Permission denied: real_time_detection required")
    except HTTPException as e:
        if e.status_code == 403:
            raise e
        # If auth fails, allow access for now (backward compatibility)
        pass
    
    global real_time_detector, capture_thread, is_capturing, current_interface, current_model, current_use_all_models
    
    if is_capturing:
        return {"message": "⚠️ Real-time detection is already running"}
    
    # Validate interface before starting
    is_valid, validation_message = validate_interface(config.interface)
    if not is_valid:
        available_interfaces = get_available_interfaces()
        return {
            "error": validation_message,
            "available_interfaces": available_interfaces,
            "suggestion": "Please select one of the available interfaces above"
        }
    
    try:
        # Ensure previous detector is stopped
        if real_time_detector:
            real_time_detector.stop_capture()
            if capture_thread and capture_thread.is_alive():
                capture_thread.join(timeout=5)  # Wait for thread to end, max 5 seconds
        
        real_time_detector = RealTimeDetector(config.model)
        capture_thread = threading.Thread(
            target=real_time_detector.start_capture,
            args=(config.interface, config.use_all_models),
            daemon=True,
            name="NetworkCaptureThread"
        )
        capture_thread.start()
        is_capturing = True
        
        # Store current configuration
        current_interface = config.interface
        current_model = config.model
        current_use_all_models = config.use_all_models
        
        return {
            "message": f"✅ Real-time threat detection started",
            "interface": config.interface,
            "model": config.model,
            "use_all_models": config.use_all_models,
            "status": "running"
        }
        
    except Exception as e:
        # Ensure cleanup on error
        is_capturing = False
        real_time_detector = None
        capture_thread = None
        current_interface = None
        current_model = None
        current_use_all_models = None
        return {"error": f"Failed to start: {str(e)}"}

@app.post("/stop-realtime")
def stop_realtime_detection():
    global real_time_detector, capture_thread, is_capturing, current_interface, current_model, current_use_all_models
    
    if not is_capturing:
        return {"message": "⚠️ Real-time detection is not running"}
    
    try:
        if real_time_detector:
            real_time_detector.stop_capture()
        
        # Wait for thread to end
        if capture_thread and capture_thread.is_alive():
            capture_thread.join(timeout=10)  # Wait max 10 seconds
            if capture_thread.is_alive():
                print("⚠️ Capture thread did not terminate normally")
        
        is_capturing = False
        real_time_detector = None
        capture_thread = None
        current_interface = None
        current_model = None
        current_use_all_models = None
        
        return {"message": "⏹️ Real-time threat detection stopped", "status": "stopped"}
        
    except Exception as e:
        return {"error": f"Failed to stop: {str(e)}"}

@app.get("/realtime-status")
def get_realtime_status():
    global current_interface, current_model, current_use_all_models
    thread_status = "running" if capture_thread and capture_thread.is_alive() else "stopped"
    return {
        "is_capturing": is_capturing,
        "thread_status": thread_status,
        "status": "running" if is_capturing and thread_status == "running" else "stopped",
        "current_interface": current_interface,
        "current_model": current_model,
        "current_use_all_models": current_use_all_models
    }

# Import new modules



