# app/alert_system.py
import asyncio
import json
import logging
from datetime import datetime
from app.timezone_utils import get_beijing_time, get_beijing_time_iso, timedelta
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from dataclasses import dataclass, asdict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import JSONResponse
from pymongo import MongoClient
import os
from collections import defaultdict, deque
import threading
import time
import uuid
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# MongoDB connection (prefer environment variable for cloud deployment)
client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client['PreTectNIDS']
alerts_collection = db['alerts']
alert_rules_collection = db['alert_rules']
alert_history_collection = db['alert_history']

class AlertLevel(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertType(str, Enum):
    """Types of alerts"""
    THREAT_DETECTED = "threat_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    MULTIPLE_ATTACKS = "multiple_attacks"
    SUSPICIOUS_IP = "suspicious_ip"
    HIGH_RISK_PORT = "high_risk_port"
    ZERO_DAY_ATTACK = "zero_day_attack"
    BRUTE_FORCE = "brute_force"
    SYSTEM_OVERLOAD = "system_overload"

@dataclass
class AlertRule:
    """Alert rule configuration"""
    id: str
    name: str
    description: str
    alert_type: AlertType
    conditions: Dict[str, Any]
    actions: List[str]
    enabled: bool = True
    threshold: Optional[float] = None
    time_window: Optional[int] = None  # minutes
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

@dataclass
class Alert:
    """Alert data structure"""
    id: str
    rule_id: str
    alert_type: AlertType
    level: AlertLevel
    title: str
    message: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None  # New: destination IP
    target_port: Optional[int] = None
    protocol: Optional[str] = None       # New: protocol type
    model: Optional[str] = None
    confidence: Optional[float] = None
    threat_details: Optional[Dict] = None
    timestamp: Optional[str] = None
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    attack_type: Optional[str] = None  # Added: attack type (e.g., BENIGN, DDoS, Port Scan)

class AlertManager:
    """Central alert management system"""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.alert_rules: Dict[str, AlertRule] = {}
        self.recent_alerts: deque = deque(maxlen=1000)
        self.alert_counts: Dict[str, int] = defaultdict(int)
        self.ip_alert_counts: Dict[str, int] = defaultdict(int)
        self.port_alert_counts: Dict[int, int] = defaultdict(int)
        self.ip_port_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))  # For Port Scan detection
        # Cache for model decision thresholds (loaded from model files if available)
        self.model_thresholds: Dict[str, float] = {}
        self._load_alert_rules()
        self._load_model_thresholds()
        self._start_cleanup_task()
    
    def _load_alert_rules(self):
        """Load alert rules from database"""
        try:
            rules = alert_rules_collection.find({"enabled": True})
            for rule_data in rules:
                # Remove MongoDB's _id field before creating AlertRule object
                if '_id' in rule_data:
                    del rule_data['_id']
                rule = AlertRule(**rule_data)
                self.alert_rules[rule.id] = rule
            
            # Create default rules if none exist
            if not self.alert_rules:
                self._create_default_rules()
                
            logger.info(f"Loaded {len(self.alert_rules)} alert rules")
        except Exception as e:
            logger.error(f"Error loading alert rules: {e}")
            self._create_default_rules()
    
    def _create_default_rules(self):
        """Create default alert rules"""
        default_rules = [
            AlertRule(
                id="threat_detection",
                name="Threat Detection Alert",
                description="Triggered when any ML model detects a threat",
                alert_type=AlertType.THREAT_DETECTED,
                conditions={"prediction": "Attack"},
                actions=["websocket", "log", "store"],
                threshold=0.7
            ),
            AlertRule(
                id="high_confidence_threat",
                name="High Confidence Threat",
                description="Triggered for high-confidence threat detections",
                alert_type=AlertType.THREAT_DETECTED,
                conditions={"prediction": "Attack", "min_confidence": 0.9},
                actions=["websocket", "log", "store", "email"],
                threshold=0.9
            ),
            AlertRule(
                id="multiple_attacks_same_ip",
                name="Multiple Attacks from Same IP",
                description="Multiple attacks detected from the same source IP",
                alert_type=AlertType.MULTIPLE_ATTACKS,
                conditions={"same_ip_count": 5},
                actions=["websocket", "log", "store"],
                time_window=15
            ),
            AlertRule(
                id="suspicious_ports",
                name="Suspicious Port Access",
                description="Access to commonly attacked ports",
                alert_type=AlertType.HIGH_RISK_PORT,
                conditions={"ports": [22, 23, 80, 443, 8080, 8180, 8009, 3389, 445, 135, 21]},
                actions=["websocket", "log", "store"]
            ),
            AlertRule(
                id="zero_day_detection",
                name="Zero-day Attack Detection",
                description="Kitsune model detects potential zero-day attack",
                alert_type=AlertType.ZERO_DAY_ATTACK,
                conditions={"model": "Kitsune", "prediction": "Attack"},
                actions=["websocket", "log", "store", "email"],
                threshold=0.02
            ),
            AlertRule(
                id="brute_force_detection",
                name="Brute Force Attack",
                description="Multiple failed login attempts detected",
                alert_type=AlertType.BRUTE_FORCE,
                conditions={"ports": [22, 23, 3389, 21], "repeat_count": 5},
                actions=["websocket", "log", "store"],
                time_window=5
            ),
            AlertRule(
                id="ssh_brute_force_detection",
                name="SSH Brute Force Attack",
                description="SSH brute force attack detected on port 22",
                alert_type=AlertType.BRUTE_FORCE,
                conditions={"ports": [22], "repeat_count": 3},
                actions=["websocket", "log", "store"],
                time_window=3
            ),
            # New comprehensive rules:
            AlertRule(
                id="port_scan_detection",
                name="Port Scan Detected",
                description="Multiple ports accessed from same IP in short time (possible scan)",
                alert_type=AlertType.ANOMALY_DETECTED,
                conditions={"ports_scanned": 10, "time_window": 2},
                actions=["websocket", "log", "store"]
            ),
            AlertRule(
                id="ddos_detection",
                name="DDoS Attack Detected",
                description="High volume of connections from many IPs (possible DDoS)",
                alert_type=AlertType.ANOMALY_DETECTED,
                conditions={"unique_ips": 50, "connection_rate": 1000, "time_window": 1},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="suspicious_country",
                name="Suspicious Country Source",
                description="Traffic from high-risk or geo-blocked country",
                alert_type=AlertType.SUSPICIOUS_IP,
                conditions={"country": ["RU", "CN", "KP", "IR", "SY"]},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="malware_traffic",
                name="Malware Traffic Pattern",
                description="Traffic matches known malware C2 pattern",
                alert_type=AlertType.THREAT_DETECTED,
                conditions={"malware_signature": True},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="ransomware_behavior",
                name="Ransomware Behavior",
                description="Rapid file access and encryption pattern detected",
                alert_type=AlertType.ANOMALY_DETECTED,
                conditions={"ransomware_behavior": True},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="data_exfiltration",
                name="Data Exfiltration",
                description="Large outbound data transfer detected",
                alert_type=AlertType.ANOMALY_DETECTED,
                conditions={"outbound_data_mb": 100, "time_window": 5},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="privilege_escalation",
                name="Privilege Escalation Attempt",
                description="Unusual privilege escalation detected",
                alert_type=AlertType.ANOMALY_DETECTED,
                conditions={"privilege_escalation": True},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="lateral_movement",
                name="Lateral Movement",
                description="Suspicious lateral movement in network",
                alert_type=AlertType.ANOMALY_DETECTED,
                conditions={"lateral_movement": True},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="phishing_attempt",
                name="Phishing Attempt",
                description="Traffic pattern matches known phishing campaign",
                alert_type=AlertType.THREAT_DETECTED,
                conditions={"phishing_signature": True},
                actions=["websocket", "log", "store", "email"]
            ),
            AlertRule(
                id="internal_recon",
                name="Internal Reconnaissance",
                description="Internal host scanning other internal hosts",
                alert_type=AlertType.ANOMALY_DETECTED,
                conditions={"internal_scan": True},
                actions=["websocket", "log", "store"]
            ),
            AlertRule(
                id="unauthorized_access",
                name="Unauthorized Access Attempt",
                description="Access to restricted resource detected",
                alert_type=AlertType.THREAT_DETECTED,
                conditions={"unauthorized_access": True},
                actions=["websocket", "log", "store", "email"]
            ),
        ]
        for rule in default_rules:
            rule.created_at = get_beijing_time_iso()
            rule.updated_at = rule.created_at
            self.alert_rules[rule.id] = rule
            alert_rules_collection.insert_one(asdict(rule))
        logger.info("Created default alert rules")
    
    def _start_cleanup_task(self):
        """Start background task to clean up old data"""
        def cleanup_task():
            while True:
                try:
                    # Clean up old alert counts every 5 minutes
                    self.alert_counts.clear()
                    time.sleep(300)  # 5 minutes
                except Exception as e:
                    logger.error(f"Cleanup task error: {e}")
                    time.sleep(60)
        
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
    
    def _load_model_thresholds(self):
        """Load model decision thresholds from files if available (cached)."""
        try:
            # Known threshold files in models directory
            candidates = {
                "Autoencoder": "models/ae_threshold.txt",
                "Kitsune": "models/kitsune_threshold.txt",
                "CNN-DNN": "models/cnn_dnn_threshold.txt",
                "RandomForest": "models/rf_threshold.txt",
                "LSTM": "models/lstm_threshold.txt",
            }
            for model_name, path in candidates.items():
                if os.path.exists(path):
                    try:
                        with open(path, "r") as f:
                            value = float(f.read().strip())
                            self.model_thresholds[model_name] = value
                    except Exception:
                        # Ignore malformed file; keep default empty
                        pass
            logger.info(f"Loaded model thresholds: {self.model_thresholds}")
        except Exception as e:
            logger.warning(f"Failed to load model thresholds: {e}")

    def _get_model_threshold(self, result: Dict) -> Optional[float]:
        """Resolve decision threshold for current model.
        Priority: result['threshold'] > cached threshold by model name > None.
        """
        # Prefer threshold carried in model result
        if isinstance(result, dict) and 'threshold' in result:
            try:
                return float(result['threshold'])
            except Exception:
                pass
        model_name = result.get('model') if isinstance(result, dict) else None
        if model_name and model_name in self.model_thresholds:
            return self.model_thresholds[model_name]
        return None

    async def add_connection(self, websocket: WebSocket):
        """Add new WebSocket connection"""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"New WebSocket connection added. Total: {len(self.active_connections)}")
    
    async def remove_connection(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket connection removed. Total: {len(self.active_connections)}")
    
    async def broadcast_alert(self, alert: Alert):
        """Broadcast alert to all connected clients"""
        logger.info(f"📡 Broadcasting alert: {alert.title} to {len(self.active_connections)} connected clients")
        
        if not self.active_connections:
            logger.warning("❌ No WebSocket connections available for alert broadcast")
            return
        
        alert_data = asdict(alert)
        message = {
            "type": "alert",
            "data": alert_data
        }
        
        message_json = json.dumps(message)
        logger.debug(f"   Alert message: {message_json[:200]}...")
        
        disconnected = set()
        sent_count = 0
        for websocket in self.active_connections:
            try:
                await websocket.send_text(message_json)
                sent_count += 1
                logger.debug(f"   ✅ Alert sent to client {id(websocket)}")
            except Exception as e:
                logger.warning(f"   ❌ Failed to send alert to client {id(websocket)}: {e}")
                disconnected.add(websocket)
        
        # Remove disconnected clients
        for websocket in disconnected:
            self.active_connections.discard(websocket)
            logger.info(f"   🗑️ Removed disconnected client {id(websocket)}")
        
        logger.info(f"   📤 Alert broadcast complete: {sent_count} clients notified, {len(disconnected)} clients disconnected")
    
    def process_detection_result(self, detection_data: Dict):
        """Process detection result and generate alerts if needed"""
        try:
            result = detection_data.get('result', {})
            features = detection_data.get('features', [])
            detection_type = detection_data.get('type', 'unknown')
            model = result.get('model', 'Unknown')
            prediction = result.get('prediction', 'Normal')
            attack_type = detection_data.get('attack_type') or result.get('attack_type') or result.get('Label')
            
            # Debug: Log the prediction value
            print(f"🔍 Alert Debug - Original prediction: '{prediction}' (length: {len(prediction) if prediction else 0})")
            print(f"🔍 Alert Debug - Prediction type: {type(prediction)}")
            print(f"🔍 Alert Debug - Full result: {result}")
            
            # Extract meta info if available
            source_ip = detection_data.get('src_ip') or self._extract_source_ip(detection_data)
            destination_ip = detection_data.get('dst_ip') or detection_data.get('destination_ip')
            target_port = detection_data.get('dst_port') or detection_data.get('target_port') or self._extract_target_port(features)
            protocol = detection_data.get('protocol')
            
            # Calculate confidence for alert level determination (not for filtering)
            confidence = self._calculate_confidence(result)
            
            # Check if this is an attack detection
            is_attack = prediction in ['Attack', 1]
            
            if is_attack:
                # This is an attack - generate alert immediately
                logger.info(f"🚨 ATTACK DETECTED by {model}: {prediction} (confidence: {confidence:.3f})")
                logger.info(f"   Source IP: {source_ip}, Target Port: {target_port}, Protocol: {protocol}")
                
                # Update counters
                if source_ip:
                    self.ip_alert_counts[source_ip] += 1
                    logger.info(f"   Updated IP alert count for {source_ip}: {self.ip_alert_counts[source_ip]}")
                if target_port:
                    self.port_alert_counts[target_port] += 1
                    logger.info(f"   Updated port alert count for {target_port}: {self.port_alert_counts[target_port]}")
                # Also update port history even for attack traffic to enable port-scan detection
                if source_ip and target_port:
                    self.ip_port_history[source_ip].append((target_port, get_beijing_time()))
                    # Attach attack_type based strictly on port heuristics
                    if not attack_type and protocol in ['TCP','UDP']:
                        # SSH Brute Force
                        if target_port in [22, 2222, 2200, 2022]:
                            attack_type = 'SSH Brute Force'
                        # Tomcat/AJP attacks
                        elif target_port in [80, 443, 8080, 8180, 8009, 8443]:
                            attack_type = 'Tomcat'
                        # Reverse Shell / C2
                        elif target_port in [4444, 4445, 5555, 6666, 7777, 8888, 9999]:
                            attack_type = 'Reverse Shell'
                        # Backdoor / FTP exploits
                        elif target_port in [21, 6200, 31337, 12345, 54321]:
                            attack_type = 'Backdoor'
                        # RDP Brute Force
                        elif target_port in [3389, 3388, 3390]:
                            attack_type = 'RDP Brute Force'
                        # Telnet Brute Force
                        elif target_port in [23, 2323, 2300]:
                            attack_type = 'Telnet Brute Force'
                        # VNC attacks
                        elif target_port in [5900, 5901, 5902, 5903, 5904, 5905]:
                            attack_type = 'VNC Attack'
                        # Database attacks
                        elif target_port in [1433, 3306, 5432, 1521, 27017, 6379]:
                            attack_type = 'Database Attack'
                        # Mail server attacks
                        elif target_port in [25, 110, 143, 993, 995, 587, 465]:
                            attack_type = 'Mail Server Attack'
                        # DNS attacks
                        elif target_port in [53, 5353]:
                            attack_type = 'DNS Attack'
                        # SMB/NetBIOS attacks
                        elif target_port in [139, 445, 135]:
                            attack_type = 'SMB Attack'
                        # Web attacks (beyond Tomcat)
                        elif target_port in [8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8443, 9443]:
                            attack_type = 'Web Attack'
                        # Malware C2 common ports
                        elif target_port in [1337, 31337, 12345, 54321, 6666, 6667, 6668, 6669, 7000, 7001, 7002]:
                            attack_type = 'Malware C2'
                        # Phishing/Web exploits
                        elif target_port in [80, 443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010]:
                            attack_type = 'Phishing Attack'
                        # Ransomware communication
                        elif target_port in [443, 8443, 9443, 10443, 11443, 12443, 13443, 14443, 15443]:
                            attack_type = 'Ransomware'
                        # Cryptocurrency mining
                        elif target_port in [3333, 4444, 5555, 7777, 8888, 9999, 14444, 15555, 16666, 17777, 18888, 19999]:
                            attack_type = 'Crypto Mining'
                        # IoT device attacks
                        elif target_port in [1883, 8883, 5683, 5684, 1884, 1885, 1886, 1887, 1888, 1889, 1890]:
                            attack_type = 'IoT Attack'
                        # Industrial Control Systems
                        elif target_port in [502, 503, 504, 102, 44818, 47808, 20000, 20001, 20002, 20003, 20004, 20005]:
                            attack_type = 'ICS Attack'
                        # File sharing attacks
                        elif target_port in [2049, 111, 2048, 2047, 2046, 2045, 2044, 2043, 2042, 2041, 2040]:
                            attack_type = 'File Sharing Attack'
                        # Remote access attacks
                        elif target_port in [3389, 3388, 3390, 3391, 3392, 3393, 3394, 3395, 3396, 3397, 3398, 3399]:
                            attack_type = 'Remote Access Attack'
                        # Gaming/Entertainment (often used for C2)
                        elif target_port in [25565, 25566, 25567, 25568, 25569, 25570, 7777, 7778, 7779, 7780, 7781]:
                            attack_type = 'Gaming C2'
                        # Custom application attacks
                        elif target_port in [9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010]:
                            attack_type = 'Custom App Attack'
                        # SYN Flood (based on TCP flags)
                        elif protocol == 'TCP' and target_port and result.get('tcp_flags') == 'SYNONLY':
                            attack_type = 'SYN Flood'
                        # Port scanning (multiple ports from same IP)
                        elif target_port and len(self.ip_port_history[source_ip]) > 5:
                            attack_type = 'Port Scan'
                
                # Generate alert for each matching rule
                rules_checked = 0
                alerts_generated = 0
                for rule in self.alert_rules.values():
                    if not rule.enabled:
                        logger.debug(f"   Rule {rule.id} is disabled, skipping")
                        continue
                    
                    rules_checked += 1
                    logger.info(f"   Checking rule: {rule.id} - {rule.name}")
                    
                    if self._check_rule_conditions(rule, detection_data, result, features):
                        logger.info(f"   ✅ Rule {rule.id} conditions met, creating alert...")
                        # Prefer incoming attack_type, fallback to detection_data's inferred type
                        derived_attack_type = attack_type or detection_data.get('attack_type')
                        alert = self._create_alert(
                            rule, detection_data, result, source_ip, destination_ip, target_port, protocol, confidence, derived_attack_type
                        )
                        # Use create_task instead of asyncio.run to avoid event loop conflicts
                        try:
                            import asyncio
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                # Create task in existing loop
                                loop.create_task(self._process_alert(alert))
                            else:
                                # Run in new loop if none exists
                                asyncio.run(self._process_alert(alert))
                        except Exception as e:
                            logger.error(f"   ❌ Failed to process alert: {e}")
                            # Fallback: process alert synchronously
                            self._process_alert_sync(alert)
                        
                        alerts_generated += 1
                        logger.info(f"   ✅ Alert generated: {alert.title} [{alert.level}]")
                    else:
                        logger.warning(f"   ❌ Rule {rule.id} conditions not met for attack detection")
                
                logger.info(f"   Summary: {rules_checked} rules checked, {alerts_generated} alerts generated")
                # After generating model-based alerts, still check for port scan aggregation
                self._check_port_scan_rule(detection_data, features, source_ip, destination_ip, protocol)
            else:
                # Not an attack, but check for port scan behavior
                self._check_port_scan_rule(detection_data, features, source_ip, destination_ip, protocol)
                
                # Update port history for non-attack traffic
                if source_ip and target_port:
                    self.ip_port_history[source_ip].append((target_port, get_beijing_time()))
                    
        except Exception as e:
            logger.error(f"Error processing detection result: {e}")
            import traceback
            traceback.print_exc()

    def _check_port_scan_rule(self, detection_data: Dict, features: List, source_ip: Optional[str] = None, destination_ip: Optional[str] = None, protocol: Optional[str] = None):
        """Check for Port Scan behavior and generate alert if detected (rule-based, not model-based)"""
        PORT_SCAN_WINDOW_SECONDS = 10
        PORT_SCAN_PORT_THRESHOLD = 10
        if not source_ip:
            source_ip = self._extract_source_ip(detection_data)
        now = get_beijing_time()
        port_history = self.ip_port_history[source_ip]
        recent_ports = [port for port, t in port_history if (now - t).total_seconds() <= PORT_SCAN_WINDOW_SECONDS]
        unique_ports = set(recent_ports)
        if len(unique_ports) >= PORT_SCAN_PORT_THRESHOLD:
            alert = Alert(
                id=str(uuid.uuid4()),
                rule_id="port_scan_rule",
                alert_type=AlertType.ANOMALY_DETECTED,
                level=AlertLevel.HIGH,
                title=f"Port Scan Detected from {source_ip}",
                message=f"Port scan behavior detected: Source IP {source_ip} accessed {len(unique_ports)} different ports in {PORT_SCAN_WINDOW_SECONDS} seconds.",
                source_ip=source_ip,
                destination_ip=destination_ip,
                target_port=None,
                protocol=protocol,
                model="Rule-based",
                confidence=1.0,
                threat_details={
                    'ports_scanned': list(unique_ports),
                    'window_seconds': PORT_SCAN_WINDOW_SECONDS
                },
                timestamp=get_beijing_time_iso(),
                attack_type="Port Scan"
            )
            # Use create_task instead of asyncio.run to avoid event loop conflicts
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Create task in existing loop
                    loop.create_task(self._process_alert(alert))
                else:
                    # Run in new loop if none exists
                    asyncio.run(self._process_alert(alert))
            except Exception as e:
                logger.error(f"Failed to process port scan alert: {e}")
                # Fallback: process alert synchronously
                self._process_alert_sync(alert)
            
            self.ip_port_history[source_ip].clear()
    
    def _extract_source_ip(self, detection_data: Dict) -> Optional[str]:
        """Extract source IP from detection data"""
        # This would be enhanced to extract actual IP from network features
        # For now, simulate with a placeholder
        interface = detection_data.get('interface', 'unknown')
        if interface != 'unknown':
            # Generate a realistic-looking source IP for demo
            import random
            return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        return None
    
    def _extract_target_port(self, features: List) -> Optional[int]:
        """Extract target port from features"""
        if len(features) >= 3:
            port = int(features[2]) if features[2] > 0 else None
            return port
        return None
    
    def _calculate_confidence(self, result: Dict) -> float:
        """Calculate confidence using ratio-based mapping against model threshold.
        - For probability models: use prob / threshold (if threshold known), else fallback to prob mapping.
        - For anomaly score models: use score / threshold (if threshold known), else fallback to heuristic.
        """
        threshold = self._get_model_threshold(result)
        # Probability-based models
        if 'probability' in result:
            prob = float(result['probability'])
            if threshold and threshold > 0:
                ratio = prob / float(threshold)
                if ratio > 5:
                    return 0.95
                elif ratio > 2:
                    return 0.85
                elif ratio > 1:
                    return 0.70
                else:
                    return 0.60
            # Fallback if no threshold known
            if prob >= 0.95:
                return 0.95
            elif prob >= 0.85:
                return 0.85
            elif prob >= 0.70:
                return 0.70
            else:
                return 0.60
        # Anomaly-score models
        if 'anomaly_score' in result:
            score = float(result['anomaly_score'])
            if threshold and threshold > 0:
                ratio = score / float(threshold)
                if ratio > 5:
                    return 0.95
                elif ratio > 2:
                    return 0.85
                elif ratio > 1:
                    return 0.75
                elif ratio > 0.5:
                    return 0.65
                else:
                    return 0.55
            # Fallback heuristic if threshold unknown
            if score > 10000:
                return 0.95
            elif score > 1000:
                return 0.85
            elif score > 100:
                return 0.75
            elif score > 10:
                return 0.65
            else:
                return 0.55
        return 0.6
    
    def _check_rule_conditions(self, rule: AlertRule, detection_data: Dict, result: Dict, features: List) -> bool:
        """Check if alert rule conditions are met"""
        conditions = rule.conditions
        
        # Check prediction condition (most important)
        if 'prediction' in conditions:
            if result.get('prediction') != conditions['prediction']:
                logger.info(f"❌ Rule {rule.id}: prediction mismatch - expected {conditions['prediction']}, got {result.get('prediction')}")
                return False
        
        # Check model condition
        if 'model' in conditions:
            if result.get('model') != conditions['model']:
                logger.debug(f"Rule {rule.id}: model mismatch - expected {conditions['model']}, got {result.get('model')}")
                return False
        
        # Check confidence threshold (only if explicitly specified)
        if 'min_confidence' in conditions:
            confidence = self._calculate_confidence(result)
            if confidence < conditions['min_confidence']:
                logger.debug(f"Rule {rule.id}: confidence too low - {confidence:.3f} < {conditions['min_confidence']}")
                return False
        
        # Check rule threshold (only if explicitly specified)
        if rule.threshold is not None:
            confidence = self._calculate_confidence(result)
            if confidence < rule.threshold:
                logger.debug(f"Rule {rule.id}: threshold not met - {confidence:.3f} < {rule.threshold}")
                return False
        
        # Check port conditions
        if 'ports' in conditions:
            target_port = self._extract_target_port(features)
            if target_port not in conditions['ports']:
                logger.debug(f"Rule {rule.id}: port {target_port} not in allowed ports {conditions['ports']}")
                return False
        
        # Check IP repeat conditions
        if 'same_ip_count' in conditions:
            source_ip = self._extract_source_ip(detection_data)
            if source_ip and self.ip_alert_counts[source_ip] < conditions['same_ip_count']:
                logger.debug(f"Rule {rule.id}: IP {source_ip} count {self.ip_alert_counts[source_ip]} < {conditions['same_ip_count']}")
                return False
        
        # Check repeat count for brute force
        if 'repeat_count' in conditions:
            target_port = self._extract_target_port(features)
            if target_port and self.port_alert_counts[target_port] < conditions['repeat_count']:
                logger.debug(f"Rule {rule.id}: port {target_port} count {self.port_alert_counts[target_port]} < {conditions['repeat_count']}")
                return False
        
        logger.info(f"✅ Rule {rule.id}: all conditions met")
        return True
    
    def _create_alert(self, rule: AlertRule, detection_data: Dict, result: Dict, 
                     source_ip: Optional[str], destination_ip: Optional[str], target_port: Optional[int], protocol: Optional[str], confidence: float, attack_type: Optional[str] = None) -> Alert:
        """Create alert from rule and detection data"""
        alert_id = str(uuid.uuid4())
        if confidence >= 0.9 or rule.alert_type == AlertType.ZERO_DAY_ATTACK:
            level = AlertLevel.CRITICAL
        elif confidence >= 0.8:
            level = AlertLevel.HIGH
        elif confidence >= 0.6:
            level = AlertLevel.MEDIUM
        else:
            level = AlertLevel.LOW
        model = result.get('model', 'Unknown')
        title = self._generate_alert_title(rule, model, source_ip, target_port, attack_type)
        message = self._generate_alert_message(rule, result, source_ip, target_port, confidence, attack_type)
        threat_details = {
            'detection_type': detection_data.get('type', 'unknown'),
            'model_result': result,
            'raw_features': detection_data.get('features', [])[:10],
            'interface': detection_data.get('interface'),
            'alert_rule': rule.name
        }
        return Alert(
            id=alert_id,
            rule_id=rule.id,
            alert_type=rule.alert_type,
            level=level,
            title=title,
            message=message,
            source_ip=source_ip,
            destination_ip=destination_ip,
            target_port=target_port,
            protocol=protocol,
            model=model,
            confidence=confidence,
            threat_details=threat_details,
            timestamp=get_beijing_time_iso(),
            attack_type=attack_type
        )
    
    def _generate_alert_title(self, rule: AlertRule, model: str, source_ip: Optional[str], target_port: Optional[int], attack_type: Optional[str] = None) -> str:
        """Generate alert title based on attack type and context (improved, more specific)"""
        if attack_type:
            attack_titles = {
                "DDoS": f"DDoS Attack Detected from {source_ip}",
                "Port Scan": f"Port Scan Activity from {source_ip}",
                "Brute Force": f"Brute Force Attack from {source_ip}",
                "Malware": f"Malware Traffic Pattern Detected",
                "Ransomware": f"Ransomware Behavior Detected",
                "Data Exfiltration": f"Data Exfiltration Attempt from {source_ip}",
                "Privilege Escalation": f"Privilege Escalation Attempt from {source_ip}",
                "Lateral Movement": f"Lateral Movement Detected",
                "Phishing": f"Phishing Attempt Detected",
                "Internal Reconnaissance": f"Internal Reconnaissance Detected",
                "Unauthorized Access": f"Unauthorized Access Attempt from {source_ip}",
                "Suspicious Country": f"Suspicious Country Source: {source_ip}",
                "High Risk Port": f"High Risk Port Access on {target_port}",
                "Reverse Shell": f"Reverse Shell Connection from {source_ip}",
                "Backdoor": f"Backdoor Exploitation Activity from {source_ip}",
                "Tomcat": f"Tomcat Service Targeted on Port {target_port}",
                "SSH Brute Force": f"SSH Brute Force from {source_ip}",
                "SYN Flood": f"SYN Flood Detected targeting {target_port}",
                "RDP Brute Force": f"RDP Brute Force from {source_ip}",
                "Telnet Brute Force": f"Telnet Brute Force from {source_ip}",
                "VNC Attack": f"VNC Attack from {source_ip}",
                "Database Attack": f"Database Attack on Port {target_port}",
                "Mail Server Attack": f"Mail Server Attack on Port {target_port}",
                "DNS Attack": f"DNS Attack on Port {target_port}",
                "SMB Attack": f"SMB/NetBIOS Attack on Port {target_port}",
                "Web Attack": f"Web Attack on Port {target_port}",
                "Malware C2": f"Malware C2 Communication on Port {target_port}",
                "Phishing Attack": f"Phishing Attack on Port {target_port}",
                "Ransomware": f"Ransomware Communication on Port {target_port}",
                "Crypto Mining": f"Cryptocurrency Mining on Port {target_port}",
                "IoT Attack": f"IoT Device Attack on Port {target_port}",
                "ICS Attack": f"Industrial Control System Attack on Port {target_port}",
                "File Sharing Attack": f"File Sharing Attack on Port {target_port}",
                "Remote Access Attack": f"Remote Access Attack on Port {target_port}",
                "Gaming C2": f"Gaming C2 Communication on Port {target_port}",
                "Custom App Attack": f"Custom Application Attack on Port {target_port}",
                "Port Scan": f"Port Scan Activity from {source_ip}",
                "BENIGN": f"Benign Traffic from {source_ip}"
            }
            return attack_titles.get(attack_type, f"{attack_type} Detected from {source_ip}")
        # Fallback to rule-based title
        titles = {
            AlertType.THREAT_DETECTED: f"🚨 Threat Detected by {model}",
            AlertType.ZERO_DAY_ATTACK: f"⚠️ Potential Zero-day Attack Detected",
            AlertType.MULTIPLE_ATTACKS: f"🔄 Multiple Attacks from {source_ip or 'Unknown IP'}",
            AlertType.HIGH_RISK_PORT: f"🎯 Suspicious Access to Port {target_port}",
            AlertType.BRUTE_FORCE: f"🔓 Brute Force Attack on Port {target_port}",
            AlertType.ANOMALY_DETECTED: f"📊 Unusual Network Behavior Detected"
        }
        return titles.get(rule.alert_type, f"⚠️ Security Alert: {rule.name}")

    def _generate_alert_message(self, rule: AlertRule, result: Dict, source_ip: Optional[str], 
                               target_port: Optional[int], confidence: float, attack_type: Optional[str] = None) -> str:
        """Generate detailed alert message based on attack type and context (improved, more specific)"""
        model = result.get('model', 'Unknown')
        confidence_pct = confidence * 100
        if attack_type:
            attack_messages = {
                "DDoS": f"A Distributed Denial of Service (DDoS) attack was detected. Source IP: {source_ip}. High volume of traffic targeting port {target_port}. Immediate mitigation is recommended.",
                "Port Scan": f"Port scan activity detected: {source_ip} attempted to access multiple ports in a short period. This may indicate reconnaissance.",
                "Brute Force": f"Brute force attack suspected: Multiple failed login attempts from {source_ip} targeting port {target_port}.", 
                "Malware": f"Malware-like traffic pattern detected from {source_ip}. Communication resembles known malware command-and-control channels. Immediate isolation is recommended.",
                "Ransomware": f"Ransomware behavior detected: Rapid file access and encryption patterns observed from {source_ip}. Immediate response required.",
                "Data Exfiltration": f"Possible data exfiltration: Large outbound data transfer detected from {source_ip}. Review for potential data breach.",
                "Privilege Escalation": f"Privilege escalation attempt detected: Unusual access rights change from {source_ip}. Investigate for possible compromise.",
                "Lateral Movement": f"Lateral movement detected: {source_ip} is accessing multiple internal hosts, which may indicate attacker pivoting.",
                "Phishing": f"Phishing attempt detected: Traffic from {source_ip} matches known phishing campaign patterns.",
                "Internal Reconnaissance": f"Internal reconnaissance detected: {source_ip} is scanning other internal hosts.",
                "Unauthorized Access": f"Unauthorized access attempt: {source_ip} tried to access restricted resources on port {target_port}.",
                "Suspicious Country": f"Suspicious traffic from high-risk country detected. Source IP: {source_ip}. Review geolocation and block if necessary.",
                "High Risk Port": f"Suspicious activity detected on high-risk port {target_port}. Source IP: {source_ip}.",
                "Reverse Shell": f"Potential reverse shell connection detected from {source_ip} to port {target_port}. Investigate outbound connections and block suspicious sessions.",
                "Backdoor": f"Potential backdoor exploitation activity observed from {source_ip}. Check for unauthorized service responses and spawned shells.",
                "Tomcat": f"Traffic targeting Tomcat-related port {target_port} detected with malicious indicators. Review Tomcat/AJP exposure, authentication and patch level.",
                "SSH Brute Force": f"SSH brute force behavior detected from {source_ip} against port {target_port}. Implement lockout/MFA and review auth logs.",
                "SYN Flood": f"SYN flood pattern detected targeting port {target_port}. Consider rate limiting and SYN cookies on perimeter devices.",
                "RDP Brute Force": f"RDP brute force attack detected from {source_ip} against port {target_port}. Enable Network Level Authentication and strong passwords.",
                "Telnet Brute Force": f"Telnet brute force attack detected from {source_ip} against port {target_port}. Disable Telnet and use SSH instead.",
                "VNC Attack": f"VNC attack detected from {source_ip} against port {target_port}. Secure VNC with strong passwords and VPN access.",
                "Database Attack": f"Database attack detected from {source_ip} against port {target_port}. Review database access controls and enable encryption.",
                "Mail Server Attack": f"Mail server attack detected from {source_ip} against port {target_port}. Implement SPF, DKIM, and DMARC policies.",
                "DNS Attack": f"DNS attack detected from {source_ip} against port {target_port}. Monitor for DNS tunneling and cache poisoning attempts.",
                "SMB Attack": f"SMB/NetBIOS attack detected from {source_ip} against port {target_port}. Disable SMBv1 and implement strong authentication.",
                "Web Attack": f"Web application attack detected from {source_ip} against port {target_port}. Review web application security and implement WAF.",
                "Malware C2": f"Malware command and control communication detected from {source_ip} on port {target_port}. Isolate affected systems immediately.",
                "Phishing Attack": f"Phishing attack detected from {source_ip} against port {target_port}. Implement email security controls and user training.",
                "Ransomware": f"Ransomware communication detected from {source_ip} on port {target_port}. Isolate systems and check for encryption activities.",
                "Crypto Mining": f"Cryptocurrency mining activity detected from {source_ip} on port {target_port}. Check for unauthorized mining software.",
                "IoT Attack": f"IoT device attack detected from {source_ip} against port {target_port}. Secure IoT devices and implement network segmentation.",
                "ICS Attack": f"Industrial Control System attack detected from {source_ip} against port {target_port}. Isolate OT networks and review SCADA security.",
                "File Sharing Attack": f"File sharing attack detected from {source_ip} against port {target_port}. Review file sharing permissions and access controls.",
                "Remote Access Attack": f"Remote access attack detected from {source_ip} against port {target_port}. Implement VPN and multi-factor authentication.",
                "Gaming C2": f"Gaming-related command and control communication detected from {source_ip} on port {target_port}. Check for unauthorized gaming software.",
                "Custom App Attack": f"Custom application attack detected from {source_ip} against port {target_port}. Review application security and access controls.",
                "Port Scan": f"Port scanning activity detected from {source_ip}. Monitor for reconnaissance activities and potential follow-up attacks.",
                "BENIGN": f"Benign traffic detected from {source_ip}. No action required."
            }
            return attack_messages.get(attack_type, f"{attack_type} detected from {source_ip}. Target port: {target_port}. Model: {model}. Confidence: {confidence_pct:.1f}%. Immediate investigation recommended.")
        # Fallback to rule-based message
        base_msg = f"Security alert triggered by rule '{rule.name}'. "
        if rule.alert_type == AlertType.THREAT_DETECTED:
            base_msg += f"The {model} model detected malicious activity with {confidence_pct:.1f}% confidence."
        elif rule.alert_type == AlertType.ZERO_DAY_ATTACK:
            base_msg += f"Kitsune detected potential zero-day attack with anomaly score {result.get('anomaly_score', 0):.4f}."
        elif rule.alert_type == AlertType.MULTIPLE_ATTACKS:
            base_msg += f"Multiple attack attempts detected from source IP {source_ip}."
        elif rule.alert_type == AlertType.HIGH_RISK_PORT:
            base_msg += f"Suspicious activity detected on high-risk port {target_port}."
        elif rule.alert_type == AlertType.BRUTE_FORCE:
            base_msg += f"Potential brute force attack detected against port {target_port}."
        if source_ip:
            base_msg += f" Source IP: {source_ip}."
        if target_port:
            base_msg += f" Target port: {target_port}."
        base_msg += " Immediate investigation recommended."
        return base_msg
    
    async def _process_alert(self, alert: Alert):
        """Process and distribute alert"""
        try:
            # Add to recent alerts
            self.recent_alerts.append(alert)
            
            # Store in database
            alerts_collection.insert_one(asdict(alert))
            
            # Store in alert history
            history_entry = {
                'alert_id': alert.id,
                'action': 'created',
                'timestamp': get_beijing_time_iso(),
                'details': f"Alert created: {alert.title}"
            }
            alert_history_collection.insert_one(history_entry)
            
            # Execute alert actions
            rule = self.alert_rules.get(alert.rule_id)
            if rule:
                await self._execute_alert_actions(alert, rule.actions)
            
            logger.info(f"Alert processed: {alert.title} [{alert.level}]")
        
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def _process_alert_sync(self, alert: Alert):
        """Synchronous fallback for alert processing when async is not available"""
        try:
            # Add to recent alerts
            self.recent_alerts.append(alert)
            
            # Store in database
            alerts_collection.insert_one(asdict(alert))
            
            # Store in alert history
            history_entry = {
                'alert_id': alert.id,
                'action': 'created',
                'timestamp': get_beijing_time_iso(),
                'details': f"Alert created: {alert.title}"
            }
            alert_history_collection.insert_one(history_entry)
            
            # Execute alert actions synchronously
            rule = self.alert_rules.get(alert.rule_id)
            if rule:
                # Create a new event loop for this thread if needed
                try:
                    import asyncio
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(self._execute_alert_actions(alert, rule.actions))
                    loop.close()
                except Exception as e:
                    logger.error(f"Failed to execute alert actions: {e}")
                    # At least log the alert
                    logger.warning(f"SECURITY ALERT: {alert.title} - {alert.message}")
            
            logger.info(f"Alert processed (sync): {alert.title} [{alert.level}]")
        
        except Exception as e:
            logger.error(f"Error processing alert (sync): {e}")
    
    async def _execute_alert_actions(self, alert: Alert, actions: List[str]):
        """Execute alert actions"""
        # Reduced suppression: only suppress identical alerts within 5 seconds (was 30s)
        # Exclude the current alert (already appended to recent_alerts upstream)
        now = get_beijing_time()
        recent_same = [a for a in list(self.recent_alerts)[-50:]
                       if a.id != alert.id and a.source_ip == alert.source_ip
                       and a.alert_type == alert.alert_type and a.level == alert.level
                       and a.model == alert.model
                       and (now - datetime.fromisoformat(a.timestamp.replace('Z', '+00:00'))).total_seconds() < 5]
        for action in actions:
            try:
                if action == "websocket":
                    if not recent_same:
                        await self.broadcast_alert(alert)
                elif action == "log":
                    logger.warning(f"SECURITY ALERT: {alert.title} - {alert.message}")
                elif action == "store":
                    # Already stored above
                    pass
                elif action == "email":
                    # Placeholder for email notification
                    logger.info(f"Email notification would be sent for: {alert.title}")
                # Add more actions as needed
            except Exception as e:
                logger.error(f"Error executing action {action}: {e}")
    
    def get_alerts_with_pagination(self, page: int = 1, per_page: int = 100, 
                                 start_date: Optional[str] = None, 
                                 end_date: Optional[str] = None,
                                 level_filter: Optional[str] = None,
                                 resolved_filter: Optional[bool] = None) -> Dict:
        """Get alerts with pagination and filtering"""
        try:
            # Build query filter
            query_filter = {}
            
            # Date range filter
            if start_date or end_date:
                date_filter = {}
                if start_date:
                    date_filter["$gte"] = start_date
                if end_date:
                    date_filter["$lte"] = end_date
                if date_filter:
                    query_filter["timestamp"] = date_filter
            
            # Level filter
            if level_filter and level_filter != 'all':
                query_filter["level"] = level_filter
            
            # Resolved filter
            if resolved_filter is not None:
                query_filter["resolved"] = resolved_filter
                logger.info(f"🔍 Applied resolved filter: {resolved_filter}")
            else:
                logger.info("🔍 No resolved filter applied - showing all alerts")
            
            logger.info(f"🔍 Final query filter: {query_filter}")
            
            # Get total count
            total_alerts = alerts_collection.count_documents(query_filter)
            
            # Calculate pagination
            skip = (page - 1) * per_page
            total_pages = (total_alerts + per_page - 1) // per_page
            
            # Get alerts with pagination
            alerts_cursor = alerts_collection.find(query_filter).sort("timestamp", -1).skip(skip).limit(per_page)
            alerts_list = list(alerts_cursor)
            
            logger.info(f"Found {len(alerts_list)} alerts (page {page}/{total_pages}, total: {total_alerts})")
            
            # Convert ObjectId to string for JSON serialization
            for alert in alerts_list:
                if '_id' in alert:
                    alert['_id'] = str(alert['_id'])
            

            
            return {
                "alerts": alerts_list,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total_alerts": total_alerts,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                }
            }
        except Exception as e:
            logger.error(f"Error getting alerts with pagination: {e}")
            # Fallback to memory alerts
            memory_alerts = [asdict(alert) for alert in list(self.recent_alerts)[-per_page:]]
            return {
                "alerts": memory_alerts,
                "pagination": {
                    "page": 1,
                    "per_page": per_page,
                    "total_alerts": len(memory_alerts),
                    "total_pages": 1,
                    "has_next": False,
                    "has_prev": False
                }
            }
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts from database (backward compatibility)"""
        try:
            # Get alerts from database, sorted by timestamp descending
            recent_alerts = alerts_collection.find().sort("timestamp", -1).limit(limit)
            alerts_list = list(recent_alerts)
            
            logger.info(f"Found {len(alerts_list)} alerts in database")
            
            # Convert ObjectId to string for JSON serialization
            for alert in alerts_list:
                if '_id' in alert:
                    alert['_id'] = str(alert['_id'])
            
            return alerts_list
        except Exception as e:
            logger.error(f"Error getting recent alerts from database: {e}")
            # Fallback to memory alerts
            return [asdict(alert) for alert in list(self.recent_alerts)[-limit:]]
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        now = get_beijing_time()
        
        # Count alerts by level in last 24 hours
        yesterday = now - timedelta(hours=24)
        recent_alerts = alerts_collection.find({
            "timestamp": {"$gte": yesterday.isoformat()}
        })
        
        stats = {
            "total_alerts_24h": 0,
            "by_level": defaultdict(int),
            "by_type": defaultdict(int),
            "top_source_ips": defaultdict(int),
            "top_target_ports": defaultdict(int),
            "active_rules": len([r for r in self.alert_rules.values() if r.enabled])
        }
        
        for alert_data in recent_alerts:
            stats["total_alerts_24h"] += 1
            level_value = alert_data.get("level", "unknown")
            # Normalize to lowercase strings (handle Enum, mixed-case, or dict values)
            try:
                if isinstance(level_value, dict) and 'value' in level_value:
                    level_value = str(level_value['value'])
                level_key = str(level_value).lower()
            except Exception:
                level_key = "unknown"
            stats["by_level"][level_key] += 1
            stats["by_type"][alert_data.get("alert_type", "unknown")] += 1
            
            if alert_data.get("source_ip"):
                stats["top_source_ips"][alert_data["source_ip"]] += 1
            if alert_data.get("target_port"):
                stats["top_target_ports"][alert_data["target_port"]] += 1
        
        # Convert to regular dicts and get top 5
        stats["by_level"] = dict(stats["by_level"])
        stats["by_type"] = dict(stats["by_type"])
        stats["top_source_ips"] = dict(sorted(stats["top_source_ips"].items(), 
                                            key=lambda x: x[1], reverse=True)[:5])
        stats["top_target_ports"] = dict(sorted(stats["top_target_ports"].items(), 
                                               key=lambda x: x[1], reverse=True)[:5])
        
        return stats

    def get_rule_by_id(self, rule_id: str) -> Optional[AlertRule]:
        return self.alert_rules.get(rule_id)

    def update_rule(self, rule_id: str, update_data: dict) -> Optional[AlertRule]:
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None
        for key, value in update_data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.updated_at = get_beijing_time_iso()
        self.alert_rules[rule_id] = rule
        alert_rules_collection.update_one({"id": rule_id}, {"$set": asdict(rule)})
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        if rule_id in self.alert_rules:
            del self.alert_rules[rule_id]
            alert_rules_collection.delete_one({"id": rule_id})
            return True
        return False

# Global alert manager instance
alert_manager = AlertManager()

# WebSocket endpoint for real-time alerts
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time alert notifications"""
    await alert_manager.add_connection(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Handle client messages if needed (ping/pong, acknowledgments, etc.)
            
    except WebSocketDisconnect:
        await alert_manager.remove_connection(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await alert_manager.remove_connection(websocket)

# REST API endpoints
@router.get("/recent")
async def get_recent_alerts(limit: int = 50):
    """Get recent alerts (backward compatibility)"""
    try:
        alerts = alert_manager.get_recent_alerts(limit)
        return {"success": True, "alerts": alerts}
    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/alerts")
async def get_alerts_with_pagination(
    page: int = 1,
    per_page: int = 100,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    level_filter: Optional[str] = None,
    resolved_filter: Optional[bool] = None
):
    """Get alerts with pagination and filtering"""
    try:
        result = alert_manager.get_alerts_with_pagination(
            page=page,
            per_page=per_page,
            start_date=start_date,
            end_date=end_date,
            level_filter=level_filter,
            resolved_filter=resolved_filter
        )
        return {"success": True, **result}
    except Exception as e:
        logger.error(f"Error getting alerts with pagination: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/statistics")
async def get_alert_statistics():
    """Get alert statistics"""
    try:
        stats = alert_manager.get_alert_statistics()
        return {"success": True, "statistics": stats}
    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, request: Request):
    logger.info(f"DEBUG: acknowledge_alert function called with alert_id: {alert_id}")
    try:
        from app.auth import get_current_user_from_request
        logger.info(f"DEBUG: About to call get_current_user_from_request")
        try:
            user = await get_current_user_from_request(request)
            username = user.get("username", "unknown")
            logger.info(f"DEBUG: User authenticated: {username}")
        except Exception as auth_error:
            logger.error(f"DEBUG: Authentication error: {auth_error}")
            raise HTTPException(status_code=401, detail=f"Authentication failed: {str(auth_error)}")
        logger.info(f"DEBUG: Attempting to acknowledge alert with ID: {alert_id}")
        alert_check = alerts_collection.find_one({"id": alert_id})
        if alert_check:
            logger.info(f"DEBUG: Alert found in database: {alert_check.get('id')}")
        else:
            logger.warning(f"DEBUG: Alert not found in database for ID: {alert_id}")
            sample_alert = alerts_collection.find_one()
            if sample_alert:
                logger.info(f"DEBUG: Sample alert structure: {sample_alert}")
        result = alerts_collection.update_one(
            {"id": alert_id},
            {
                "$set": {
                    "acknowledged": True,
                    "acknowledged_by": username,
                    "acknowledged_at": get_beijing_time_iso()
                }
            }
        )
        logger.info(f"DEBUG: Update result - matched: {result.matched_count}, modified: {result.modified_count}")
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        history_entry = {
            'alert_id': alert_id,
            'action': 'acknowledged',
            'user': username,
            'timestamp': get_beijing_time_iso(),
            'details': f"Alert acknowledged by {username}"
        }
        alert_history_collection.insert_one(history_entry)
        return {"success": True, "message": "Alert acknowledged"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: str, request: Request):
    logger.info(f"DEBUG: resolve_alert function called with alert_id: {alert_id}")
    try:
        from app.auth import get_current_user_from_request
        logger.info(f"DEBUG: About to call get_current_user_from_request")
        try:
            user = await get_current_user_from_request(request)
            username = user.get("username", "unknown")
            logger.info(f"DEBUG: User authenticated: {username}")
        except Exception as auth_error:
            logger.error(f"DEBUG: Authentication error: {auth_error}")
            raise HTTPException(status_code=401, detail=f"Authentication failed: {str(auth_error)}")
        logger.info(f"DEBUG: Attempting to resolve alert with ID: {alert_id}")
        alert_check = alerts_collection.find_one({"id": alert_id})
        if alert_check:
            logger.info(f"DEBUG: Alert found in database: {alert_check.get('id')}")
        else:
            logger.warning(f"DEBUG: Alert not found in database for ID: {alert_id}")
            sample_alert = alerts_collection.find_one()
            if sample_alert:
                logger.info(f"DEBUG: Sample alert structure: {sample_alert}")
        result = alerts_collection.update_one(
            {"id": alert_id},
            {
                "$set": {
                    "resolved": True,
                    "resolved_by": username,
                    "resolved_at": get_beijing_time_iso()
                }
            }
        )
        logger.info(f"DEBUG: Update result - matched: {result.matched_count}, modified: {result.modified_count}")
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        history_entry = {
            'alert_id': alert_id,
            'action': 'resolved',
            'user': username,
            'timestamp': get_beijing_time_iso(),
            'details': f"Alert resolved by {username}"
        }
        alert_history_collection.insert_one(history_entry)
        return {"success": True, "message": "Alert resolved"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/rules")
async def get_alert_rules():
    """Get all alert rules"""
    try:
        rules = [asdict(rule) for rule in alert_manager.alert_rules.values()]
        return {"success": True, "rules": rules}
    except Exception as e:
        logger.error(f"Error getting alert rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rules")
async def create_alert_rule(rule_data: dict, request: Request):
    """Create new alert rule"""
    try:
        # Validate user permission
        from app.auth import get_current_user_from_request, has_permission, get_default_role
        user = await get_current_user_from_request(request)
        if not has_permission(user.get("role", get_default_role()), "alert_management"):
            raise HTTPException(status_code=403, detail="Permission denied: alert_management required")
        
        # Create rule
        rule_id = str(uuid.uuid4())
        rule_data['id'] = rule_id
        rule_data['created_at'] = get_beijing_time_iso()
        rule_data['updated_at'] = rule_data['created_at']
        
        rule = AlertRule(**rule_data)
        alert_manager.alert_rules[rule_id] = rule
        alert_rules_collection.insert_one(asdict(rule))
        
        return {"success": True, "rule_id": rule_id, "message": "Alert rule created"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating alert rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/rules/{rule_id}")
async def update_alert_rule(rule_id: str, rule_data: dict, request: Request):
    from app.auth import get_current_user_from_request, has_permission, get_default_role
    user = await get_current_user_from_request(request)
    if not has_permission(user.get("role", get_default_role()), "alert_management"):
        raise HTTPException(status_code=403, detail="Permission denied: alert_management required")
    rule = alert_manager.update_rule(rule_id, rule_data)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True, "rule": asdict(rule)}

@router.delete("/rules/{rule_id}")
async def delete_alert_rule(rule_id: str, request: Request):
    from app.auth import get_current_user_from_request, has_permission, get_default_role
    user = await get_current_user_from_request(request)
    if not has_permission(user.get("role", get_default_role()), "alert_management"):
        raise HTTPException(status_code=403, detail="Permission denied: alert_management required")
    result = alert_manager.delete_rule(rule_id)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True, "message": "Rule deleted"}

# Function to integrate with detection systems
def process_detection_for_alerts(detection_data: Dict):
    """Process detection result for alert generation"""
    alert_manager.process_detection_result(detection_data) 