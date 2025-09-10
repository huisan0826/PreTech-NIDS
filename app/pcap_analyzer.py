# app/pcap_analyzer.py
import os
import tempfile
import hashlib
import time
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timedelta
from app.timezone_utils import get_beijing_time, get_beijing_time_iso
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Ether
from scapy.layers.inet import Ether as EtherLayer
from fastapi import APIRouter, UploadFile, File, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pymongo import MongoClient
import logging
import traceback
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
from collections import defaultdict, Counter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client['PreTectNIDS']
pcap_analyses = db['pcap_analyses']
pcap_reports = db['pcap_reports']

# File size limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'.pcap', '.pcapng', '.cap'}
JSON_EXTENSIONS = {'.json'}

# Initialize global models (will be loaded when needed)
kitsune_model = None
ae_model = None
ae_scaler = None
lstm_model = None
lstm_scaler = None
cnn_model = None
cnn_scaler = None
rf_model = None
rf_scaler = None

# ---------- Thresholds (will be loaded from files if available) ----------
KITSUNE_THRESHOLD = 0.2  # Default fallback
AE_THRESHOLD = 1.0       # Default fallback  
LSTM_THRESHOLD = 10.0    # Default fallback
CNN_THRESHOLD = 0.5      # Default fallback
RF_THRESHOLD = 0.5       # Default fallback

def load_models():
    """Load all detection models and scalers"""
    global kitsune_model, ae_model, ae_scaler, lstm_model, lstm_scaler, cnn_model, cnn_scaler, rf_model, rf_scaler
    global KITSUNE_THRESHOLD, AE_THRESHOLD, LSTM_THRESHOLD, CNN_THRESHOLD, RF_THRESHOLD
    
    try:
        # Load Autoencoder model and scaler
        if os.path.exists("models/ae_model.h5") and os.path.exists("models/ae_scaler.pkl"):
            import tensorflow as tf
            import joblib
            try:
                ae_model = tf.keras.models.load_model("models/ae_model.h5")
                ae_scaler = joblib.load("models/ae_scaler.pkl")
                logger.info("✅ Autoencoder model loaded successfully")
                
                # Load threshold if available
                if os.path.exists("models/ae_threshold.txt"):
                    with open("models/ae_threshold.txt", "r") as f:
                        AE_THRESHOLD = float(f.read().strip())
                        logger.info(f"✅ Autoencoder threshold loaded: {AE_THRESHOLD}")
            except Exception as e:
                logger.error(f"Failed to load Autoencoder model: {e}")
                ae_model = None
                ae_scaler = None
        
        # Load LSTM model and scaler
        if os.path.exists("models/lstm_model.h5") and os.path.exists("models/lstm_scaler.pkl"):
            import tensorflow as tf
            import joblib
            try:
                # Load model with custom objects to handle compatibility issues
                custom_objects = {
                    'InputLayer': tf.keras.layers.InputLayer
                }
                lstm_model = tf.keras.models.load_model("models/lstm_model.h5", custom_objects=custom_objects)
                lstm_scaler = joblib.load("models/lstm_scaler.pkl")
                logger.info("✅ LSTM model loaded successfully")
                
                # Load threshold if available
                if os.path.exists("models/lstm_threshold.txt"):
                    with open("models/lstm_threshold.txt", "r") as f:
                        LSTM_THRESHOLD = float(f.read().strip())
                        logger.info(f"✅ LSTM threshold loaded: {LSTM_THRESHOLD}")
            except Exception as e:
                logger.error(f"Failed to load LSTM model: {e}")
                # Try loading with compile=False to avoid compilation issues
                try:
                    lstm_model = tf.keras.models.load_model("models/lstm_model.h5", compile=False)
                    lstm_scaler = joblib.load("models/lstm_scaler.pkl")
                    logger.info("✅ LSTM model loaded successfully (without compilation)")
                    
                    # Load threshold if available
                    if os.path.exists("models/lstm_threshold.txt"):
                        with open("models/lstm_threshold.txt", "r") as f:
                            LSTM_THRESHOLD = float(f.read().strip())
                            logger.info(f"✅ LSTM threshold loaded: {LSTM_THRESHOLD}")
                except Exception as e2:
                    logger.error(f"Failed to load LSTM model (second attempt): {e2}")
                    lstm_model = None
                    lstm_scaler = None
        
        # Load CNN-DNN model and scaler
        if os.path.exists("models/cnn_dnn_model.h5") and os.path.exists("models/cnn_dnn_scaler.pkl"):
            import tensorflow as tf
            import joblib
            try:
                # Load model with custom objects to handle compatibility issues
                custom_objects = {
                    'InputLayer': tf.keras.layers.InputLayer
                }
                cnn_model = tf.keras.models.load_model("models/cnn_dnn_model.h5", custom_objects=custom_objects)
                cnn_scaler = joblib.load("models/cnn_dnn_scaler.pkl")
                logger.info("✅ CNN-DNN model loaded successfully")
                
                # Load threshold if available
                if os.path.exists("models/cnn_dnn_threshold.txt"):
                    with open("models/cnn_dnn_threshold.txt", "r") as f:
                        CNN_THRESHOLD = float(f.read().strip())
                        logger.info(f"✅ CNN-DNN threshold loaded: {CNN_THRESHOLD}")
            except Exception as e:
                logger.error(f"Failed to load CNN-DNN model: {e}")
                # Try loading with compile=False to avoid compilation issues
                try:
                    cnn_model = tf.keras.models.load_model("models/cnn_dnn_model.h5", compile=False)
                    cnn_scaler = joblib.load("models/cnn_dnn_scaler.pkl")
                    logger.info("✅ CNN-DNN model loaded successfully (without compilation)")
                    
                    # Load threshold if available
                    if os.path.exists("models/cnn_dnn_threshold.txt"):
                        with open("models/cnn_dnn_threshold.txt", "r") as f:
                            CNN_THRESHOLD = float(f.read().strip())
                            logger.info(f"✅ CNN-DNN threshold loaded: {CNN_THRESHOLD}")
                except Exception as e2:
                    logger.error(f"Failed to load CNN-DNN model (second attempt): {e2}")
                    cnn_model = None
                    cnn_scaler = None
        
        # Load Random Forest model and scaler
        if os.path.exists("models/rf_model.pkl") and os.path.exists("models/rf_scaler.pkl"):
            import joblib
            try:
                rf_model = joblib.load("models/rf_model.pkl")
                rf_scaler = joblib.load("models/rf_scaler.pkl")
                logger.info("✅ Random Forest model loaded successfully")
                
                # Load threshold if available
                if os.path.exists("models/rf_threshold.txt"):
                    with open("models/rf_threshold.txt", "r") as f:
                        RF_THRESHOLD = float(f.read().strip())
                        logger.info(f"✅ Random Forest threshold loaded: {RF_THRESHOLD}")
                
                # Log model info for debugging
                if hasattr(rf_model, 'feature_names_in_'):
                    logger.info(f"Random Forest model has {len(rf_model.feature_names_in_)} feature names")
                else:
                    logger.info("Random Forest model has no feature names")
            except Exception as e:
                logger.error(f"Failed to load Random Forest model: {e}")
                rf_model = None
                rf_scaler = None
        
        # Load Kitsune model
        if os.path.exists("models/kitsune_model.pkl"):
            import joblib
            import sys
            import pickle
            # Add kitsune path to sys.path
            kitsune_path = os.path.join(os.path.dirname(__file__), "..", "kitsune")
            if kitsune_path not in sys.path:
                sys.path.append(kitsune_path)
            try:
                # Try loading with different protocols to handle compatibility issues
                try:
                    # First try with default protocol
                    kitsune_model = joblib.load("models/kitsune_model.pkl")
                    logger.info("✅ Kitsune model loaded successfully")
                except Exception as e1:
                    logger.warning(f"Failed to load Kitsune with joblib: {e1}")
                    # Try with pickle directly and different protocols
                    try:
                        with open("models/kitsune_model.pkl", 'rb') as f:
                            kitsune_model = pickle.load(f)
                        logger.info("✅ Kitsune model loaded successfully (with pickle)")
                    except Exception as e2:
                        logger.warning(f"Failed to load Kitsune with pickle: {e2}")
                        # Try with protocol 4 (compatible with older Python versions)
                        try:
                            with open("models/kitsune_model.pkl", 'rb') as f:
                                kitsune_model = pickle.load(f, encoding='latin1')
                            logger.info("✅ Kitsune model loaded successfully (with latin1 encoding)")
                        except Exception as e3:
                            logger.error(f"Failed to load Kitsune model (all attempts failed): {e3}")
                            kitsune_model = None
            except Exception as e:
                logger.error(f"Failed to load Kitsune model: {e}")
                kitsune_model = None
            
    except Exception as e:
        logger.error(f"❌ Error loading models: {e}")
        logger.error(traceback.format_exc())

class PcapAnalyzer:
    """Advanced PCAP file analyzer with comprehensive network feature extraction"""
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.supported_protocols = {'TCP', 'UDP', 'ICMP', 'ARP'}
        
    async def validate_file(self, file: UploadFile) -> Tuple[bool, str]:
        """Validate uploaded PCAP file with improved error handling"""
        try:
            # Check if file is provided
            if not file:
                return False, "No file provided"
            
            # Check file extension
            filename = file.filename.lower() if file.filename else ""
            logger.info(f"Validating file: {filename}")
            
            if not filename or not any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
                logger.warning(f"Invalid file type: {filename}")
                if any(filename.endswith(ext) for ext in JSON_EXTENSIONS):
                    return False, f"JSON files are not supported. Please upload a PCAP file (.pcap, .pcapng, .cap). If you have JSON data, please convert it to PCAP format first."
                return False, f"Invalid file type. Supported formats: {', '.join(ALLOWED_EXTENSIONS)}"
            
            # Check file size (read first chunk to estimate)
            content = await file.read()
            file_size = len(content)
            logger.info(f"File size: {file_size} bytes")
            
            if file_size > MAX_FILE_SIZE:
                logger.warning(f"File too large: {file_size} bytes")
                return False, f"File too large ({file_size // (1024*1024)}MB). Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"
            
            # Check if file is empty
            if file_size == 0:
                logger.warning("File is empty")
                return False, "File is empty"
            
            # Reset file pointer for later reading
            await file.seek(0)
            
            logger.info("File validation passed")
            return True, "File validation passed"
            
        except Exception as e:
            logger.error(f"File validation error: {e}")
            logger.error(traceback.format_exc())
            return False, f"File validation error: {str(e)}"
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of the file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def extract_packet_features(self, packet) -> Optional[List[float]]:
        """Extract 77 network features from a single packet with deterministic values"""
        try:
            features = []
            
            # Initialize default values
            packet_len = len(packet)
            src_port = 0
            dst_port = 0
            tcp_flags = 0
            tcp_window = 0
            tcp_seq = 0
            tcp_ack = 0
            ip_ttl = 0
            ip_id = 0
            ip_frag = 0
            protocol = 0
            
            # Extract IP layer information
            if packet.haslayer(IP):
                ip = packet[IP]
                ip_ttl = ip.ttl
                ip_id = ip.id
                ip_frag = ip.frag
                protocol = ip.proto
                
                # Extract transport layer information
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    tcp_flags = tcp.flags
                    tcp_window = tcp.window
                    tcp_seq = tcp.seq
                    tcp_ack = tcp.ack
                    protocol = 6  # TCP
                    
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    protocol = 17  # UDP
                    
                elif packet.haslayer(ICMP):
                    protocol = 1  # ICMP
            
            # Basic packet features (first 11 features)
            features.extend([
                float(packet_len),     # 0: Packet length
                float(src_port),       # 1: Source port
                float(dst_port),       # 2: Destination port
                float(int(tcp_flags)),      # 3: TCP flags 
                float(tcp_window),     # 4: TCP window size
                float(tcp_seq),        # 5: TCP sequence number
                float(tcp_ack),        # 6: TCP acknowledgment number
                float(ip_ttl),         # 7: IP TTL
                float(ip_id),          # 8: IP ID
                float(ip_frag),        # 9: IP fragment offset
                float(protocol)        # 10: Protocol number
            ])
            
            # Additional statistical features (66 more features to reach 77)
            # Use deterministic values based on packet properties instead of random numbers
            
            # Payload size features
            payload_size = len(packet.payload) if hasattr(packet, 'payload') else 0
            header_size = packet_len - payload_size
            
            # Port-based features
            port_entropy = self._calculate_port_entropy(src_port, dst_port)
            is_well_known_port = 1.0 if (dst_port < 1024 or src_port < 1024) else 0.0
            
            # Protocol features
            is_tcp = 1.0 if protocol == 6 else 0.0
            is_udp = 1.0 if protocol == 17 else 0.0
            is_icmp = 1.0 if protocol == 1 else 0.0
            
            # Packet size distribution features
            size_category = self._categorize_packet_size(packet_len)
            
            # TCP-specific features
            tcp_flag_features = self._extract_tcp_flag_features(tcp_flags)
            
            # Additional derived features
            features.extend([
                float(payload_size),           # 11: Payload size
                float(header_size),            # 12: Header size
                port_entropy,                  # 13: Port entropy
                is_well_known_port,            # 14: Well-known port indicator
                is_tcp,                        # 15: TCP protocol indicator
                is_udp,                        # 16: UDP protocol indicator
                is_icmp,                       # 17: ICMP protocol indicator
                size_category,                 # 18: Packet size category
            ])
            
            # TCP flag features (8 features)
            features.extend(tcp_flag_features)  # 19-26
            
            # Flow simulation features (remaining features to reach 77)
            # Use deterministic values based on packet properties
            remaining_features = 77 - len(features)
            for i in range(remaining_features):
                if i < 10:
                    # Flow statistics based on packet properties
                    features.append(float(packet_len) / 1500.0)  # Normalized packet size
                elif i < 20:
                    # Timing features based on packet properties
                    features.append(float(protocol) / 255.0)  # Normalized protocol
                elif i < 30:
                    # Size distribution features
                    features.append(float(src_port) / 65535.0)  # Normalized source port
                elif i < 40:
                    # Protocol distribution features
                    features.append(float(dst_port) / 65535.0)  # Normalized destination port
                else:
                    # Additional derived features based on packet properties
                    features.append(float(ip_ttl) / 255.0)  # Normalized TTL
            
            # Ensure exactly 77 features
            features = features[:77]
            while len(features) < 77:
                features.append(0.0)
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            logger.error(traceback.format_exc())
            return None
    
    def _calculate_port_entropy(self, src_port: int, dst_port: int) -> float:
        """Calculate entropy based on port numbers"""
        ports = [src_port, dst_port]
        port_counts = Counter(ports)
        total = len(ports)
        entropy = 0.0
        for count in port_counts.values():
            if count > 0:
                prob = count / total
                entropy -= prob * np.log2(prob)
        return entropy
    
    def _categorize_packet_size(self, packet_len: int) -> float:
        """Categorize packet size into ranges"""
        if packet_len < 64:
            return 0.1  # Very small
        elif packet_len < 128:
            return 0.3  # Small
        elif packet_len < 512:
            return 0.5  # Medium
        elif packet_len < 1024:
            return 0.7  # Large
        else:
            return 0.9  # Very large
    
    def _extract_tcp_flag_features(self, tcp_flags: int) -> List[float]:
        """Extract individual TCP flag features"""
        # TCP flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR
        flag_names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        flag_features = []
        
        for i, flag_name in enumerate(flag_names):
            flag_bit = 1 << i
            flag_features.append(1.0 if (tcp_flags & flag_bit) else 0.0)
        
        return flag_features
    
    def analyze_pcap_file(self, file_path: str, filename: str) -> Dict[str, Any]:
        """Comprehensive PCAP file analysis"""
        try:
            logger.info(f"Starting analysis of {filename}")
            
            # Read packets from PCAP file
            packets = rdpcap(file_path)
            total_packets = len(packets)
            
            if total_packets == 0:
                raise ValueError("No packets found in PCAP file")
            
            logger.info(f"Loaded {total_packets} packets from {filename}")
            
            # Initialize analysis results
            analysis_results = {
                'filename': filename,
                'total_packets': total_packets,
                'file_size': os.path.getsize(file_path),
                'file_hash': self.calculate_file_hash(file_path),
                'analysis_timestamp': get_beijing_time_iso(),
                'packet_details': [],
                'protocol_distribution': defaultdict(int),
                'port_analysis': defaultdict(int),
                'packet_sizes': [],
                'detection_results': [],
                'summary_statistics': {},
                'threat_analysis': {
                    'total_threats': 0,
                    'threat_types': defaultdict(int),
                    'threat_models': defaultdict(int),
                    'high_risk_packets': []
                }
            }
            
            # Analyze packets in batches for better performance
            batch_size = 100
            processed_packets = 0
            
            for i in range(0, total_packets, batch_size):
                batch_end = min(i + batch_size, total_packets)
                batch_packets = packets[i:batch_end]
                
                # Process batch
                batch_results = self._process_packet_batch(batch_packets, i)
                
                # Merge results
                analysis_results['packet_details'].extend(batch_results['packet_details'])
                analysis_results['detection_results'].extend(batch_results['detection_results'])
                
                            # Update statistics
            for protocol, count in batch_results['protocol_distribution'].items():
                analysis_results['protocol_distribution'][protocol] += count
            
            for port, count in batch_results['port_analysis'].items():
                # Convert port to string for MongoDB compatibility
                analysis_results['port_analysis'][str(port)] += count
                
                analysis_results['packet_sizes'].extend(batch_results['packet_sizes'])
                
                processed_packets += len(batch_packets)
                logger.info(f"Processed {processed_packets}/{total_packets} packets")
            
            # Generate summary statistics
            analysis_results['summary_statistics'] = self._generate_summary_statistics(analysis_results)
            
            # Perform threat analysis
            analysis_results['threat_analysis'] = self._perform_threat_analysis(analysis_results)
            
            logger.info(f"Analysis completed for {filename}")
            return analysis_results
            
        except Exception as e:
            logger.error(f"PCAP analysis error: {e}")
            logger.error(traceback.format_exc())
            raise
    
    def _process_packet_batch(self, packets: List, start_index: int) -> Dict[str, Any]:
        """Process a batch of packets"""
        batch_results = {
            'packet_details': [],
            'detection_results': [],
            'protocol_distribution': defaultdict(int),
            'port_analysis': defaultdict(int),
            'packet_sizes': []
        }
        
        for i, packet in enumerate(packets):
            packet_index = start_index + i
            
            try:
                # Extract packet information
                packet_info = self._extract_packet_info(packet, packet_index)
                batch_results['packet_details'].append(packet_info)
                
                # Extract features for detection
                features = self.extract_packet_features(packet)
                if features:
                    # Perform detection using all models
                    detection_result = self._detect_threats(features, packet_info)
                    detection_result['packet_index'] = packet_index
                    batch_results['detection_results'].append(detection_result)
                
                # Update statistics
                protocol = packet_info.get('protocol', 'Unknown')
                batch_results['protocol_distribution'][protocol] += 1
                
                dst_port = packet_info.get('dst_port')
                if dst_port:
                    # Convert port to string for MongoDB compatibility
                    batch_results['port_analysis'][str(dst_port)] += 1
                
                batch_results['packet_sizes'].append(packet_info.get('packet_length', 0))
                
            except Exception as e:
                logger.warning(f"Error processing packet {packet_index}: {e}")
                continue
        
        return batch_results
    
    def _extract_packet_info(self, packet, packet_index: int) -> Dict[str, Any]:
        """Extract basic information from a packet"""
        packet_info = {
            'packet_index': packet_index,
            'timestamp': float(packet.time) if hasattr(packet, 'time') else time.time(),
            'packet_length': len(packet),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'has_payload': bool(packet.payload) if hasattr(packet, 'payload') else False
        }
        
        try:
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info['src_ip'] = ip.src
                packet_info['dst_ip'] = ip.dst
                
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = tcp.sport
                    packet_info['dst_port'] = tcp.dport
                    packet_info['tcp_flags'] = int(tcp.flags)  # Convert FlagValue to int for MongoDB compatibility
                    
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = udp.sport
                    packet_info['dst_port'] = udp.dport
                    
                elif packet.haslayer(ICMP):
                    packet_info['protocol'] = 'ICMP'
                    
            elif packet.haslayer(ARP):
                packet_info['protocol'] = 'ARP'
                
        except Exception as e:
            logger.warning(f"Error extracting packet info: {e}")
        
        return packet_info
    
    def _detect_threats(self, features: List[float], packet_info: Dict) -> Dict[str, Any]:
        """Perform threat detection using multiple models"""
        global kitsune_model, ae_model, ae_scaler, lstm_model, lstm_scaler, cnn_model, cnn_scaler, rf_model, rf_scaler
        global KITSUNE_THRESHOLD, AE_THRESHOLD, LSTM_THRESHOLD, CNN_THRESHOLD, RF_THRESHOLD
        
        detection_results = {
            'packet_info': packet_info,
            'features': features,
            'model_results': [],
            'is_threat': False,
            'threat_confidence': 0.0,
            'threat_types': []
        }
        
        features_array = np.array(features)
        
        # Check if any models are loaded
        models_loaded = any([
            kitsune_model is not None,
            ae_model is not None,
            lstm_model is not None,
            cnn_model is not None,
            rf_model is not None
        ])
        
        if not models_loaded:
            logger.warning("No models loaded for threat detection")
            detection_results['model_results'].append({
                'model': 'No Models',
                'prediction': 'Error',
                'error': 'No detection models available'
            })
            return detection_results
        
        # Kitsune detection
        if kitsune_model:
            try:
                # Pad features to 100 dimensions for Kitsune model
                if len(features_array) < 100:
                    padded_features = np.pad(features_array, (0, 100 - len(features_array)), 'constant')
                else:
                    padded_features = features_array[:100]
                
                # Kitsune model is now a pickle file, use execute method
                score = kitsune_model.execute(padded_features)
                
                is_attack = score > KITSUNE_THRESHOLD
                
                result = {
                    'model': 'Kitsune',
                    'anomaly_score': float(score),
                    'threshold': KITSUNE_THRESHOLD,
                    'prediction': 'Attack' if is_attack else 'Normal',
                    'confidence': min(float(score / KITSUNE_THRESHOLD), 2.0)
                }
                detection_results['model_results'].append(result)
                
                if is_attack:
                    detection_results['is_threat'] = True
                    detection_results['threat_confidence'] = max(detection_results['threat_confidence'], result['confidence'])
                    detection_results['threat_types'].append('Zero-day Attack')
                    
            except Exception as e:
                logger.warning(f"Kitsune detection error: {e}")
        
        # Autoencoder detection
        if ae_model and ae_scaler:
            try:
                # Handle feature names for StandardScaler
                if hasattr(ae_scaler, 'feature_names_in_'):
                    import pandas as pd
                    X_df = pd.DataFrame(features_array.reshape(1, -1), columns=ae_scaler.feature_names_in_)
                    X = ae_scaler.transform(X_df)
                else:
                    X = ae_scaler.transform(features_array.reshape(1, -1))
                recon = ae_model.predict(X, verbose=0)
                mse = float(np.mean(np.square(X - recon)))
                is_attack = mse > AE_THRESHOLD
                
                result = {
                    'model': 'Autoencoder',
                    'anomaly_score': mse,
                    'threshold': AE_THRESHOLD,
                    'prediction': 'Attack' if is_attack else 'Normal',
                    'confidence': min(mse / AE_THRESHOLD, 2.0)
                }
                detection_results['model_results'].append(result)
                
                if is_attack:
                    detection_results['is_threat'] = True
                    detection_results['threat_confidence'] = max(detection_results['threat_confidence'], result['confidence'])
                    detection_results['threat_types'].append('Anomalous Behavior')
                    
            except Exception as e:
                logger.warning(f"Autoencoder detection error: {e}")
        
        # CNN detection
        if cnn_model and cnn_scaler:
            try:
                # Handle feature names for StandardScaler
                if hasattr(cnn_scaler, 'feature_names_in_'):
                    import pandas as pd
                    X_df = pd.DataFrame(features_array.reshape(1, -1), columns=cnn_scaler.feature_names_in_)
                    X = cnn_scaler.transform(X_df)
                else:
                    X = cnn_scaler.transform(features_array.reshape(1, -1))
                X = np.expand_dims(X, axis=-1)
                prob = cnn_model.predict(X, verbose=0)[0][0]
                is_attack = prob >= CNN_THRESHOLD
                
                result = {
                    'model': 'CNN-DNN',
                    'probability': float(prob),
                    'threshold': CNN_THRESHOLD,
                    'prediction': 'Attack' if is_attack else 'Normal',
                    'confidence': float(prob) if is_attack else float(1 - prob)
                }
                detection_results['model_results'].append(result)
                
                if is_attack:
                    detection_results['is_threat'] = True
                    detection_results['threat_confidence'] = max(detection_results['threat_confidence'], result['confidence'])
                    detection_results['threat_types'].append('Known Attack Pattern')
                    
            except Exception as e:
                logger.warning(f"CNN detection error: {e}")
        
        # Random Forest detection
        if rf_model and rf_scaler:
            try:
                # Handle feature names for StandardScaler
                if hasattr(rf_scaler, 'feature_names_in_'):
                    import pandas as pd
                    X_df = pd.DataFrame(features_array.reshape(1, -1), columns=rf_scaler.feature_names_in_)
                    X = rf_scaler.transform(X_df)
                else:
                    X = rf_scaler.transform(features_array.reshape(1, -1))
                # Handle feature names if model was trained with them
                if hasattr(rf_model, 'feature_names_in_'):
                    # Create a DataFrame with feature names to match training
                    import pandas as pd
                    X_df = pd.DataFrame(X, columns=rf_model.feature_names_in_)
                    prediction = int(rf_model.predict(X_df)[0])
                    prob = float(rf_model.predict_proba(X_df)[0][1])
                else:
                    # Use numpy array directly if no feature names
                    prediction = int(rf_model.predict(X)[0])
                    prob = float(rf_model.predict_proba(X)[0][1])
                is_attack = prediction == 1
                
                result = {
                    'model': 'Random Forest',
                    'probability': prob,
                    'threshold': RF_THRESHOLD,
                    'prediction': 'Attack' if is_attack else 'Normal',
                    'confidence': prob if is_attack else (1 - prob)
                }
                detection_results['model_results'].append(result)
                
                if is_attack:
                    detection_results['is_threat'] = True
                    detection_results['threat_confidence'] = max(detection_results['threat_confidence'], result['confidence'])
                    detection_results['threat_types'].append('Malicious Classification')
                    
            except Exception as e:
                logger.warning(f"Random Forest detection error: {e}")
        
        # Note: LSTM detection is skipped for single packet analysis
        # LSTM models require time series data (packet sequences), not individual packets
        # For flow-level analysis, LSTM would be more appropriate
        
        # Remove duplicates from threat types
        detection_results['threat_types'] = list(set(detection_results['threat_types']))
        
        return detection_results
    
    def _generate_summary_statistics(self, analysis_results: Dict) -> Dict[str, Any]:
        """Generate summary statistics from analysis results"""
        packet_sizes = analysis_results['packet_sizes']
        detection_results = analysis_results['detection_results']
        
        # Basic statistics
        stats = {
            'total_packets': len(packet_sizes),
            'packet_size_stats': {
                'min': min(packet_sizes) if packet_sizes else 0,
                'max': max(packet_sizes) if packet_sizes else 0,
                'mean': np.mean(packet_sizes) if packet_sizes else 0,
                'median': np.median(packet_sizes) if packet_sizes else 0,
                'std': np.std(packet_sizes) if packet_sizes else 0
            },
            'protocol_distribution': dict(analysis_results['protocol_distribution']),
            'top_ports': {str(k): v for k, v in sorted(analysis_results['port_analysis'].items(), 
                                   key=lambda x: x[1], reverse=True)[:10]},
            'detection_summary': {
                'total_detections': len(detection_results),
                'threat_packets': len([r for r in detection_results if r['is_threat']]),
                'normal_packets': len([r for r in detection_results if not r['is_threat']])
            }
        }
        
        # Calculate threat percentage
        if stats['detection_summary']['total_detections'] > 0:
            threat_rate = (stats['detection_summary']['threat_packets'] / 
                          stats['detection_summary']['total_detections']) * 100
            stats['detection_summary']['threat_percentage'] = round(threat_rate, 2)
        else:
            stats['detection_summary']['threat_percentage'] = 0.0
        
        return stats
    
    def _perform_threat_analysis(self, analysis_results: Dict) -> Dict[str, Any]:
        """Perform comprehensive threat analysis"""
        detection_results = analysis_results['detection_results']
        threat_packets = [r for r in detection_results if r['is_threat']]
        
        threat_analysis = {
            'total_threats': len(threat_packets),
            'threat_types': defaultdict(int),
            'threat_models': defaultdict(int),
            'high_risk_packets': [],
            'threat_timeline': [],
            'risk_assessment': 'Low'
        }
        
        # Analyze threat types and models
        for threat in threat_packets:
            for threat_type in threat['threat_types']:
                threat_analysis['threat_types'][threat_type] += 1
            
            for model_result in threat['model_results']:
                if model_result['prediction'] == 'Attack':
                    threat_analysis['threat_models'][model_result['model']] += 1
            
            # Identify high-risk packets (confidence > 1.5)
            if threat['threat_confidence'] > 1.5:
                threat_analysis['high_risk_packets'].append({
                    'packet_index': threat['packet_info']['packet_index'],
                    'confidence': threat['threat_confidence'],
                    'threat_types': threat['threat_types'],
                    'src_ip': threat['packet_info'].get('src_ip'),
                    'dst_ip': threat['packet_info'].get('dst_ip'),
                    'dst_port': threat['packet_info'].get('dst_port')
                })
        
        # Risk assessment
        total_packets = analysis_results['total_packets']
        if threat_analysis['total_threats'] > 0:
            threat_percentage = (threat_analysis['total_threats'] / total_packets) * 100
            
            if threat_percentage > 20:
                threat_analysis['risk_assessment'] = 'Critical'
            elif threat_percentage > 10:
                threat_analysis['risk_assessment'] = 'High'
            elif threat_percentage > 5:
                threat_analysis['risk_assessment'] = 'Medium'
            elif threat_percentage > 1:
                threat_analysis['risk_assessment'] = 'Low'
            else:
                threat_analysis['risk_assessment'] = 'Minimal'
        
        # Convert defaultdicts to regular dicts for JSON serialization
        threat_analysis['threat_types'] = dict(threat_analysis['threat_types'])
        threat_analysis['threat_models'] = dict(threat_analysis['threat_models'])
        
        return threat_analysis

# 实例化 PcapAnalyzer，必须在类定义之后
pcap_analyzer = PcapAnalyzer()

# API Endpoints
@router.post("/upload")
async def upload_pcap_file(request: Request, file: UploadFile = File(...)):
    """Upload and analyze PCAP file with comprehensive error handling"""
    try:
        # Import here to avoid circular imports
        from app.auth import get_current_user_from_request, has_permission, get_default_role
        
        # Check permission
        try:
            user = await get_current_user_from_request(request)
            if not has_permission(user.get("role", get_default_role()), "pcap_analysis"):
                raise HTTPException(status_code=403, detail="Permission denied: pcap_analysis required")
        except HTTPException as e:
            if e.status_code == 403:
                raise e
            # If auth fails, allow access for now (backward compatibility)
            pass
        
        # Validate file
        is_valid, message = await pcap_analyzer.validate_file(file)
        if not is_valid:
            raise HTTPException(status_code=400, detail=message)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file:
            # Read and write file content
            content = await file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        try:
            # Analyze PCAP file
            logger.info(f"Starting PCAP analysis for {file.filename}")
            logger.info(f"Temp file path: {temp_file_path}")
            logger.info(f"File size: {len(content)} bytes")
            
            # Check if file exists and is readable
            if not os.path.exists(temp_file_path):
                raise FileNotFoundError(f"Temporary file not found: {temp_file_path}")
            
            # Check file permissions
            if not os.access(temp_file_path, os.R_OK):
                raise PermissionError(f"Cannot read temporary file: {temp_file_path}")
            
            # Check available disk space
            import shutil
            total, used, free = shutil.disk_usage(os.path.dirname(temp_file_path))
            logger.info(f"Disk space - Total: {total}, Used: {used}, Free: {free}")
            
            analysis_results = pcap_analyzer.analyze_pcap_file(temp_file_path, file.filename)
            
            # Save analysis to database
            analysis_id = pcap_analyses.insert_one(analysis_results).inserted_id
            analysis_results['_id'] = str(analysis_id)
            
            # Generate comprehensive report
            report = generate_pcap_report(analysis_results)
            
            # Save report to database
            report['analysis_id'] = str(analysis_id)
            report_id = pcap_reports.insert_one(report).inserted_id
            report['_id'] = str(report_id)
            
            logger.info(f"PCAP analysis completed for {file.filename}")
            
            return {
                'success': True,
                'message': 'PCAP file analyzed successfully',
                'analysis_id': str(analysis_id),
                'report_id': str(report_id),
                'summary': {
                    'filename': file.filename,
                    'total_packets': analysis_results['total_packets'],
                    'threats_detected': analysis_results['threat_analysis']['total_threats'],
                    'risk_level': analysis_results['threat_analysis']['risk_assessment'],
                    'file_size': analysis_results['file_size']
                }
            }
            
        except Exception as analysis_error:
            logger.error(f"PCAP analysis error: {analysis_error}")
            logger.error(f"Error type: {type(analysis_error).__name__}")
            logger.error(traceback.format_exc())
            raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {str(analysis_error)}")
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except Exception as cleanup_error:
                logger.warning(f"Failed to cleanup temp file: {cleanup_error}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PCAP upload error: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@router.get("/analyses")
async def get_pcap_analyses(limit: int = 50, skip: int = 0):
    """Get list of PCAP analyses"""
    try:
        # Get analyses with pagination
        analyses = list(pcap_analyses.find(
            {},
            {'_id': 1, 'filename': 1, 'analysis_timestamp': 1, 'total_packets': 1, 
             'file_size': 1, 'threat_analysis.total_threats': 1, 'threat_analysis.risk_assessment': 1}
        ).sort('analysis_timestamp', -1).skip(skip).limit(limit))
        
        # Convert ObjectId to string
        for analysis in analyses:
            analysis['_id'] = str(analysis['_id'])
        
        total_count = pcap_analyses.count_documents({})
        
        return {
            'success': True,
            'analyses': analyses,
            'pagination': {
                'total': total_count,
                'limit': limit,
                'skip': skip,
                'has_more': skip + limit < total_count
            }
        }
        
    except Exception as e:
        logger.error(f"Get analyses error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/analysis/{analysis_id}")
async def get_pcap_analysis(analysis_id: str):
    """Get detailed PCAP analysis results"""
    try:
        from bson import ObjectId
        
        analysis = pcap_analyses.find_one({'_id': ObjectId(analysis_id)})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        analysis['_id'] = str(analysis['_id'])
        
        return {
            'success': True,
            'analysis': analysis
        }
        
    except Exception as e:
        logger.error(f"Get analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/report/{report_id}")
async def get_pcap_report(report_id: str):
    """Get PCAP analysis report"""
    try:
        from bson import ObjectId
        
        report = pcap_reports.find_one({'_id': ObjectId(report_id)})
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        report['_id'] = str(report['_id'])
        
        return {
            'success': True,
            'report': report
        }
        
    except Exception as e:
        logger.error(f"Get report error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export/{report_id}")
async def export_pcap_report(report_id: str, format: str = "pdf"):
    """Export PCAP analysis report in various formats"""
    try:
        from bson import ObjectId
        
        # Find the analysis by ID
        analysis = pcap_analyses.find_one({"_id": ObjectId(report_id)})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Generate comprehensive report
        report = generate_pcap_report(analysis)
        
        if format.lower() == "pdf":
            return await export_report_as_pdf(report)
        elif format.lower() == "json":
            return export_report_as_json(report)
        elif format.lower() == "csv":
            return export_report_as_csv(report)
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use 'pdf', 'json', or 'csv'")
        
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting report: {str(e)}")

async def export_report_as_pdf(report: Dict) -> Response:
    """Export report as PDF"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from io import BytesIO
        import tempfile
        import os
        
        # Create temporary file for PDF with better error handling
        tmp_file = None
        try:
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
            tmp_file.close()  # Close immediately to avoid file handle issues
            
            doc = SimpleDocTemplate(tmp_file.name, pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=30,
                alignment=1  # Center alignment
            )
            story.append(Paragraph("PreTech-NIDS PCAP Analysis Report", title_style))
            story.append(Spacer(1, 12))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            story.append(Spacer(1, 6))
            story.append(Paragraph(report['executive_summary'], styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Analysis Summary
            story.append(Paragraph("Analysis Summary", styles['Heading2']))
            story.append(Spacer(1, 6))
            
            summary_data = [
                ['Metric', 'Value'],
                ['Filename', report['filename']],
                ['File Hash', report['file_hash']],
                ['Total Packets', str(report['analysis_summary']['total_packets'])],
                ['File Size (MB)', str(report['analysis_summary']['file_size_mb'])],
                ['Risk Level', report['analysis_summary']['risk_level']],
                ['Generated At', report['generated_at']]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 12))
            
            # Threat Detection Results
            story.append(Paragraph("Threat Detection Results", styles['Heading2']))
            story.append(Spacer(1, 6))
            
            threat_data = report['detailed_findings']['threat_detection']
            threat_summary = [
                ['Metric', 'Value'],
                ['Total Threats', str(threat_data['total_threats'])],
                ['Risk Assessment', threat_data['risk_assessment']],
                ['Threat Types', ', '.join(threat_data['threat_types'].keys()) if threat_data['threat_types'] else 'None']
            ]
            
            threat_table = Table(threat_summary, colWidths=[2*inch, 4*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(threat_table)
            story.append(Spacer(1, 12))
            
            # Security Recommendations
            story.append(Paragraph("Security Recommendations", styles['Heading2']))
            story.append(Spacer(1, 6))
            
            for i, recommendation in enumerate(report['recommendations'], 1):
                story.append(Paragraph(f"{i}. {recommendation}", styles['Normal']))
                story.append(Spacer(1, 3))
            
            # Build PDF
            doc.build(story)
            
            # Read the generated PDF
            with open(tmp_file.name, 'rb') as pdf_file:
                pdf_content = pdf_file.read()
                
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            raise HTTPException(status_code=500, detail=f"PDF generation error: {str(e)}")
        finally:
            # Clean up temporary file with error handling
            if tmp_file and os.path.exists(tmp_file.name):
                try:
                    os.unlink(tmp_file.name)
                except OSError as e:
                    logger.warning(f"Could not delete temporary PDF file {tmp_file.name}: {e}")
                    # On Windows, sometimes the file is still in use, but that's okay
                    # The OS will clean it up later
            
            # Return PDF response
            filename = f"pcap_analysis_{report['filename'].replace('.pcap', '')}_{get_beijing_time().strftime('%Y%m%d_%H%M%S')}.pdf"
            
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
            
    except ImportError:
        raise HTTPException(status_code=500, detail="PDF generation requires reportlab library. Please install: pip install reportlab")
    except Exception as e:
        logger.error(f"PDF export error: {e}")
        raise HTTPException(status_code=500, detail=f"PDF export error: {str(e)}")

def export_report_as_json(report: Dict) -> Response:
    """Export report as JSON"""
    try:
        import json
        from datetime import datetime
        
        filename = f"pcap_analysis_{report['filename'].replace('.pcap', '')}_{get_beijing_time().strftime('%Y%m%d_%H%M%S')}.json"
        
        return Response(
            content=json.dumps(report, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        logger.error(f"JSON export error: {e}")
        raise HTTPException(status_code=500, detail=f"JSON export error: {str(e)}")

def export_report_as_csv(report: Dict) -> Response:
    """Export report as CSV"""
    try:
        import csv
        from io import StringIO
        from datetime import datetime
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['PCAP Analysis Report'])
        writer.writerow(['Generated At', report['generated_at']])
        writer.writerow(['Filename', report['filename']])
        writer.writerow(['File Hash', report['file_hash']])
        writer.writerow([])
        
        # Analysis Summary
        writer.writerow(['Analysis Summary'])
        writer.writerow(['Total Packets', report['analysis_summary']['total_packets']])
        writer.writerow(['File Size (MB)', report['analysis_summary']['file_size_mb']])
        writer.writerow(['Risk Level', report['analysis_summary']['risk_level']])
        writer.writerow([])
        
        # Threat Detection
        threat_data = report['detailed_findings']['threat_detection']
        writer.writerow(['Threat Detection Results'])
        writer.writerow(['Total Threats', threat_data['total_threats']])
        writer.writerow(['Risk Assessment', threat_data['risk_assessment']])
        writer.writerow(['Threat Types', ', '.join(threat_data['threat_types'].keys()) if threat_data['threat_types'] else 'None'])
        writer.writerow([])
        
        # Protocol Analysis
        protocol_data = report['detailed_findings']['protocol_analysis']
        writer.writerow(['Protocol Analysis'])
        for protocol, count in protocol_data.items():
            writer.writerow([protocol, count])
        writer.writerow([])
        
        # Port Analysis
        port_data = report['detailed_findings']['port_analysis']
        writer.writerow(['Top Ports'])
        for port, count in list(port_data.items())[:10]:  # Top 10 ports
            writer.writerow([port, count])
        writer.writerow([])
        
        # Security Recommendations
        writer.writerow(['Security Recommendations'])
        for i, recommendation in enumerate(report['recommendations'], 1):
            writer.writerow([f"{i}. {recommendation}"])
        
        filename = f"pcap_analysis_{report['filename'].replace('.pcap', '')}_{get_beijing_time().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        logger.error(f"CSV export error: {e}")
        raise HTTPException(status_code=500, detail=f"CSV export error: {str(e)}")

def generate_pcap_report(analysis_results: Dict) -> Dict[str, Any]:
    """Generate comprehensive PCAP analysis report"""
    
    report = {
        'report_type': 'pcap_analysis',
        'generated_at': get_beijing_time_iso(),
        'filename': analysis_results['filename'],
        'file_hash': analysis_results['file_hash'],
        'analysis_summary': {
            'total_packets': analysis_results['total_packets'],
            'file_size_mb': round(analysis_results['file_size'] / (1024 * 1024), 2),
            'analysis_duration': 'N/A',  # Could be calculated if timing is tracked
            'risk_level': analysis_results['threat_analysis']['risk_assessment']
        },
        'executive_summary': generate_executive_summary(analysis_results),
        'detailed_findings': {
            'protocol_analysis': analysis_results['summary_statistics']['protocol_distribution'],
            'port_analysis': analysis_results['summary_statistics']['top_ports'],
            'packet_size_analysis': analysis_results['summary_statistics']['packet_size_stats'],
            'threat_detection': analysis_results['threat_analysis']
        },
        'model_performance': generate_model_performance_summary(analysis_results),
        'recommendations': generate_security_recommendations(analysis_results),
        'technical_details': {
            'feature_extraction_method': '77-feature network packet analysis',
            'models_used': get_models_used(analysis_results),
            'detection_thresholds': {
                'Kitsune': 0.02,
                'Autoencoder': 0.01,
                'LSTM': 0.5,
                'CNN-DNN': 0.5,
                'Random Forest': 0.5
            }
        }
    }
    
    return report

def generate_executive_summary(analysis_results: Dict) -> str:
    """Generate executive summary for the report (improved, more specific)"""
    stats = analysis_results['summary_statistics']
    threats = analysis_results['threat_analysis']
    threat_types = list(threats['threat_types'].keys())
    top_ports = list(stats['top_ports'].keys())[:5]
    top_ips = list(threats.get('top_source_ips', []))[:3] if 'top_source_ips' in threats else []
    impact_map = {
        'DDoS': 'Service disruption',
        'Port Scan': 'Reconnaissance, vulnerability mapping',
        'Brute Force': 'Account compromise',
        'Malware': 'System infection, C2 communication',
        'Ransomware': 'Data encryption, extortion',
        'Data Exfiltration': 'Sensitive data loss',
        'Privilege Escalation': 'Elevated attacker privileges',
        'Lateral Movement': 'Internal spread',
        'Phishing': 'Credential theft',
        'Internal Reconnaissance': 'Network mapping',
        'Unauthorized Access': 'Resource compromise',
        'Suspicious Country': 'Potential APT or foreign threat',
        'High Risk Port': 'Targeted service exploitation'
    }
    possible_impact = ', '.join([impact_map.get(t, 'Unknown impact') for t in threat_types]) if threat_types else 'None'
    summary = f"""
PCAP Analysis Executive Summary for {analysis_results['filename']}

File Analysis:
- Total Packets Analyzed: {stats['total_packets']:,}
- File Size: {round(analysis_results['file_size'] / (1024 * 1024), 2)} MB
- Analysis Timestamp: {analysis_results['analysis_timestamp']}

Security Assessment:
- Risk Level: {threats['risk_assessment']}
- Total Threats Detected: {threats['total_threats']:,}
- Threat Detection Rate: {stats['detection_summary']['threat_percentage']}%

Key Findings:
- Detected Attacks: {', '.join(threat_types) if threat_types else 'None'}
- Most Targeted Ports: {', '.join(map(str, top_ports)) if top_ports else 'None'}
- Top Source IPs: {', '.join(top_ips) if top_ips else 'N/A'}
- Average Packet Size: {round(stats['packet_size_stats']['mean'], 1)} bytes

Possible Impact:
- {possible_impact}

Recommended Action:
- Block malicious IPs and review firewall rules
- Isolate affected hosts and conduct forensic analysis
- Monitor for further suspicious activity
"""
    if threats['total_threats'] == 0:
        summary += "\n- No significant threats detected in the analyzed traffic."
    return summary.strip()

def generate_model_performance_summary(analysis_results: Dict) -> Dict[str, Any]:
    """Generate model performance summary"""
    detection_results = analysis_results['detection_results']
    model_stats = defaultdict(lambda: {'detections': 0, 'total_predictions': 0})
    
    for result in detection_results:
        for model_result in result['model_results']:
            model_name = model_result['model']
            model_stats[model_name]['total_predictions'] += 1
            if model_result['prediction'] == 'Attack':
                model_stats[model_name]['detections'] += 1
    
    performance = {}
    for model, stats in model_stats.items():
        detection_rate = (stats['detections'] / stats['total_predictions'] * 100) if stats['total_predictions'] > 0 else 0
        performance[model] = {
            'total_predictions': stats['total_predictions'],
            'detections': stats['detections'],
            'detection_rate_percent': round(detection_rate, 2)
        }
    
    return performance

def generate_security_recommendations(analysis_results: Dict) -> List[str]:
    """Generate security recommendations based on analysis"""
    recommendations = []
    threats = analysis_results['threat_analysis']
    stats = analysis_results['summary_statistics']
    
    # Risk-based recommendations
    if threats['risk_assessment'] in ['Critical', 'High']:
        recommendations.extend([
            "IMMEDIATE ACTION REQUIRED: High threat activity detected",
            "Implement network segmentation to contain potential threats",
            "Enable enhanced monitoring on affected network segments",
            "Review and update intrusion detection rules"
        ])
    elif threats['risk_assessment'] == 'Medium':
        recommendations.extend([
            "Increase monitoring frequency for suspicious activities",
            "Review firewall rules for the detected traffic patterns",
            "Consider implementing additional access controls"
        ])
    
    # Protocol-specific recommendations
    if 'TCP' in stats['protocol_distribution'] and stats['protocol_distribution']['TCP'] > stats['total_packets'] * 0.8:
        recommendations.append("High TCP traffic volume - monitor for potential DDoS attacks")
    
    # Port-specific recommendations
    top_ports = stats['top_ports']
    if 22 in top_ports:  # SSH
        recommendations.append("SSH traffic detected - ensure strong authentication and key management")
    if 80 in top_ports or 443 in top_ports:  # HTTP/HTTPS
        recommendations.append("Web traffic detected - monitor for SQL injection and XSS attempts")
    if 3389 in top_ports:  # RDP
        recommendations.append("RDP traffic detected - implement multi-factor authentication")
    
    # Threat-specific recommendations
    if threats['threat_types']:
        if 'Zero-day Attack' in threats['threat_types']:
            recommendations.append("Zero-day attacks detected - update threat intelligence feeds")
        if 'Known Attack Pattern' in threats['threat_types']:
            recommendations.append("Known attack patterns detected - review and update signature databases")
    
    # General recommendations
    recommendations.extend([
        "Regularly update network security policies",
        "Conduct periodic security assessments",
        "Maintain up-to-date threat intelligence",
        "Train security personnel on emerging threats"
    ])
    
    return recommendations

def get_models_used(analysis_results: Dict) -> List[str]:
    """Get list of models used in the analysis"""
    models_used = set()
    for result in analysis_results['detection_results']:
        for model_result in result['model_results']:
            models_used.add(model_result['model'])
    return list(models_used)

# Load models on startup
load_models()

# Initialize PcapAnalyzer instance
pcap_analyzer = PcapAnalyzer() 