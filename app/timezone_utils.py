"""
Timezone utility functions for PreTech-NIDS
All times are converted to UTC+8 (Beijing timezone)
"""

from datetime import datetime, timedelta

def get_beijing_time():
    """Get current time in UTC+8 (Beijing timezone)"""
    return datetime.utcnow() + timedelta(hours=8)

def get_beijing_time_iso():
    """Get current time in UTC+8 (Beijing timezone) as ISO format string"""
    return get_beijing_time().isoformat()

def convert_utc_to_beijing(utc_time):
    """Convert UTC time to Beijing time (UTC+8)"""
    if isinstance(utc_time, str):
        utc_time = datetime.fromisoformat(utc_time.replace('Z', '+00:00'))
    return utc_time + timedelta(hours=8)

def get_beijing_time_delta(hours=0, days=0):
    """Get Beijing time with offset"""
    return get_beijing_time() + timedelta(hours=hours, days=days)
