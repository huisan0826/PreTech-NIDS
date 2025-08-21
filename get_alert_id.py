#!/usr/bin/env python3
"""
Simple script to get a real alert ID from the database for testing
"""
from pymongo import MongoClient

def get_real_alert_id():
    """Get a real alert ID from the database"""
    try:
        client = MongoClient("mongodb://localhost:27017")
        db = client['PreTectNIDS']
        alerts_collection = db['alerts']
        
        # Get the first alert
        alert = alerts_collection.find_one()
        if alert:
            print(f"Found alert with ID: {alert.get('id')}")
            print(f"Alert title: {alert.get('title', 'No title')}")
            print(f"Alert timestamp: {alert.get('timestamp', 'No timestamp')}")
            return alert.get('id')
        else:
            print("No alerts found in database")
            return None
            
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    alert_id = get_real_alert_id()
    if alert_id:
        print(f"\nUse this ID for testing: {alert_id}")
    else:
        print("No alert ID available for testing") 