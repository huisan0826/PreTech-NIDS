# app/geomap.py
import requests
import json
import time
import re
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
from app.timezone_utils import get_beijing_time, get_beijing_time_iso
from pymongo import MongoClient
from fastapi import APIRouter, HTTPException
import asyncio
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client['PreTectNIDS']
attack_locations = db['attack_locations']
geo_cache = db['geo_cache']

class GeoIPService:
    """IP Geolocation service with caching and rate limiting"""
    
    def __init__(self):
        self.cache = {}
        self.request_times = deque()
        self.max_requests_per_hour = 1000  # Free tier limit for most services
        self.executor = ThreadPoolExecutor(max_workers=5)
        
        # Multiple geolocation services for redundancy
        self.geo_services = [
            {
                'name': 'ipapi',
                'url': 'http://ip-api.com/json/{}',
                'rate_limit': 45,  # requests per minute
                'fields': ['country', 'countryCode', 'region', 'city', 'lat', 'lon', 'isp', 'org']
            },
            {
                'name': 'ipinfo',
                'url': 'https://ipinfo.io/{}/json',
                'rate_limit': 50000,  # per month for free
                'fields': ['country', 'region', 'city', 'loc', 'org']
            }
        ]
        
        # Load cache from MongoDB
        self._load_cache_from_db()
    
    def _load_cache_from_db(self):
        """Load IP location cache from MongoDB"""
        try:
            cached_data = geo_cache.find()
            for item in cached_data:
                self.cache[item['ip']] = item['location_data']
            logger.info(f"Loaded {len(self.cache)} cached IP locations from database")
        except Exception as e:
            logger.error(f"Failed to load cache from database: {e}")
    
    def _save_to_cache(self, ip: str, location_data: dict):
        """Save IP location to cache and MongoDB"""
        self.cache[ip] = location_data
        try:
            geo_cache.update_one(
                {'ip': ip},
                {'$set': {'ip': ip, 'location_data': location_data, 'cached_at': get_beijing_time()}},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to save cache to database: {e}")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return True
    
    def _rate_limit_check(self) -> bool:
        """Check if we can make another API request"""
        now = time.time()
        # Remove requests older than 1 hour
        while self.request_times and self.request_times[0] < now - 3600:
            self.request_times.popleft()
        
        return len(self.request_times) < self.max_requests_per_hour
    
    def _get_location_from_ipapi(self, ip: str) -> Optional[dict]:
        """Get location from ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'timezone': data.get('timezone'),
                        'as': data.get('as'),
                        'source': 'ipapi'
                    }
        except Exception as e:
            logger.error(f"Error getting location from ipapi for {ip}: {e}")
        return None
    
    def _get_location_from_ipinfo(self, ip: str) -> Optional[dict]:
        """Get location from ipinfo.io (fallback)"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                loc = data.get('loc', '').split(',')
                lat, lon = None, None
                if len(loc) == 2:
                    try:
                        lat, lon = float(loc[0]), float(loc[1])
                    except:
                        pass
                
                return {
                    'country': data.get('country'),
                    'country_code': data.get('country'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'latitude': lat,
                    'longitude': lon,
                    'org': data.get('org'),
                    'timezone': data.get('timezone'),
                    'source': 'ipinfo'
                }
        except Exception as e:
            logger.error(f"Error getting location from ipinfo for {ip}: {e}")
        return None
    
    def get_ip_location(self, ip: str) -> Optional[dict]:
        """Get IP geolocation with caching"""
        # Check if IP is private
        if self._is_private_ip(ip):
            return {
                'country': 'Local Network',
                'country_code': 'LOCAL',
                'region': 'Private',
                'city': 'Internal',
                'latitude': 0,
                'longitude': 0,
                'source': 'local'
            }
        
        # Check cache first
        if ip in self.cache:
            return self.cache[ip]
        
        # Rate limiting check
        if not self._rate_limit_check():
            logger.warning(f"Rate limit exceeded, using default location for {ip}")
            return None
        
        # Try to get location from services
        location_data = None
        
        # Try primary service (ip-api.com)
        location_data = self._get_location_from_ipapi(ip)
        
        # If primary fails, try fallback service
        if not location_data:
            location_data = self._get_location_from_ipinfo(ip)
        
        # If all services fail, use unknown location
        if not location_data:
            location_data = {
                'country': 'Unknown',
                'country_code': 'UNKNOWN',
                'region': 'Unknown',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0,
                'source': 'unknown'
            }
        
        # Record request time and cache result
        self.request_times.append(time.time())
        self._save_to_cache(ip, location_data)
        
        return location_data

class AttackMapService:
    """Service for tracking attack sources and generating map data"""
    
    def __init__(self):
        self.geoip = GeoIPService()
        self.attack_buffer = deque(maxlen=1000)  # Keep last 1000 attacks
        self.country_stats = defaultdict(int)
        self.attack_lock = threading.Lock()
    
    def extract_source_ip(self, features: List[float], report_data: dict) -> Optional[str]:
        """Extract source IP from network features or report data"""
        # This is a simplified extraction - in real implementation,
        # you'd need to parse the actual network packet data
        
        # Check if IP is stored in report metadata
        if 'source_ip' in report_data:
            return report_data['source_ip']
        
        # For demo purposes, generate sample IPs based on features
        # In real implementation, this would come from actual packet capture
        if features and len(features) >= 4:
            # Use features to generate realistic-looking IPs
            # This is just for demonstration
            base_ips = [
                "203.0.113.{}",  # TEST-NET-3
                "198.51.100.{}",  # TEST-NET-2
                "192.0.2.{}",     # TEST-NET-1
                "8.8.8.{}",       # Google DNS range (for demo)
                "1.1.1.{}",       # Cloudflare range (for demo)
            ]
            
            ip_template = base_ips[int(features[3]) % len(base_ips)]
            last_octet = int(abs(features[0] + features[1]) * 255) % 254 + 1
            return ip_template.format(last_octet)
        
        return None
    
    def record_attack(self, source_ip: str, attack_details: dict):
        """Record an attack with geolocation"""
        if not source_ip:
            return
        
        # Get geolocation for the IP
        location = self.geoip.get_ip_location(source_ip)
        if not location:
            return
        
        attack_record = {
            'timestamp': get_beijing_time(),
            'source_ip': source_ip,
            'location': location,
            'attack_details': attack_details,
            'country': location.get('country', 'Unknown'),
            'country_code': location.get('country_code', 'UNKNOWN'),
            'latitude': location.get('latitude', 0),
            'longitude': location.get('longitude', 0)
        }
        
        # Thread-safe operations
        with self.attack_lock:
            self.attack_buffer.append(attack_record)
            self.country_stats[location.get('country', 'Unknown')] += 1
        
        # Save to database
        try:
            attack_locations.insert_one(attack_record)
        except Exception as e:
            logger.error(f"Failed to save attack location to database: {e}")
    
    def get_recent_attacks(self, minutes: int = 60) -> List[dict]:
        """Get recent attacks within specified time window"""
        cutoff_time = get_beijing_time() - timedelta(minutes=minutes)
        
        try:
            # Get from database for persistence
            recent_attacks = list(attack_locations.find({
                'timestamp': {'$gte': cutoff_time}
            }).sort('timestamp', -1).limit(500))
            
            # Convert ObjectId to string for JSON serialization
            for attack in recent_attacks:
                attack['_id'] = str(attack['_id'])
                attack['timestamp'] = attack['timestamp'].isoformat()
            
            return recent_attacks
        except Exception as e:
            logger.error(f"Failed to get recent attacks from database: {e}")
            return []
    
    def get_attack_statistics(self) -> dict:
        """Get attack statistics by country"""
        try:
            # Get statistics from database
            pipeline = [
                {
                    '$match': {
                        'timestamp': {
                            '$gte': get_beijing_time() - timedelta(hours=24)
                        }
                    }
                },
                {
                    '$group': {
                        '_id': {
                            'country': '$country',
                            'country_code': '$country_code'
                        },
                        'count': {'$sum': 1},
                        'latest_attack': {'$max': '$timestamp'}
                    }
                },
                {
                    '$sort': {'count': -1}
                },
                {
                    '$limit': 20
                }
            ]
            
            results = list(attack_locations.aggregate(pipeline))
            
            stats = []
            for result in results:
                stats.append({
                    'country': result['_id']['country'],
                    'country_code': result['_id']['country_code'],
                    'attack_count': result['count'],
                    'latest_attack': result['latest_attack'].isoformat()
                })
            
            return {
                'total_attacks_24h': sum(stat['attack_count'] for stat in stats),
                'countries': stats
            }
        except Exception as e:
            logger.error(f"Failed to get attack statistics: {e}")
            return {'total_attacks_24h': 0, 'countries': []}

# Global service instances
attack_map_service = AttackMapService()

# API Endpoints
@router.get("/recent-attacks")
async def get_recent_attacks(minutes: int = 60):
    """Get recent attacks for map display"""
    try:
        attacks = attack_map_service.get_recent_attacks(minutes)
        return {
            'success': True,
            'attacks': attacks,
            'count': len(attacks),
            'time_window_minutes': minutes
        }
    except Exception as e:
        logger.error(f"Error getting recent attacks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/statistics")
async def get_attack_statistics():
    """Get attack statistics by country"""
    try:
        stats = attack_map_service.get_attack_statistics()
        return {
            'success': True,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Error getting attack statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/record-attack")
async def record_attack_location(attack_data: dict):
    """Record an attack with geolocation (called by detection system)"""
    try:
        source_ip = attack_data.get('source_ip')
        if not source_ip:
            # Try to extract from features
            features = attack_data.get('features', [])
            source_ip = attack_map_service.extract_source_ip(features, attack_data)
        
        if source_ip:
            attack_map_service.record_attack(source_ip, attack_data)
            return {'success': True, 'message': 'Attack location recorded'}
        else:
            return {'success': False, 'message': 'No source IP found'}
    except Exception as e:
        logger.error(f"Error recording attack location: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Function to integrate with existing detection system
def record_threat_location(report_data: dict):
    """Function to be called from main detection system when threat is detected"""
    try:
        if report_data.get('result', {}).get('prediction') in ['Attack', 1]:
            features = report_data.get('features', [])
            source_ip = attack_map_service.extract_source_ip(features, report_data)
            
            if source_ip:
                attack_details = {
                    'model': report_data.get('result', {}).get('model'),
                    'prediction': report_data.get('result', {}).get('prediction'),
                    'anomaly_score': report_data.get('result', {}).get('anomaly_score'),
                    'probability': report_data.get('result', {}).get('probability'),
                    'detection_type': report_data.get('type', 'unknown')
                }
                
                attack_map_service.record_attack(source_ip, attack_details)
                logger.info(f"Recorded attack from IP {source_ip}")
    except Exception as e:
        logger.error(f"Error recording threat location: {e}") 