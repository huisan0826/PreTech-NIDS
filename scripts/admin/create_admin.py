#!/usr/bin/env python3
"""
Create Default Admin Account for PreTech-NIDS
This script creates a default admin account for the system.

IMPORTANT: The role must be set to "admin" (not "administrator") 
to match the UserRole.ADMIN constant in app/auth.py
"""

import sys
import os
from datetime import datetime, timedelta
from app.timezone_utils import get_beijing_time, get_beijing_time_iso

def main():
    """Main function"""
    print("🛡️ PreTech-NIDS - Creating Default Admin Account")
    print("=" * 50)
    
    try:
        # Test imports first
        print("📦 Checking required packages...")
        
        try:
            from pymongo import MongoClient
            print("   ✅ pymongo imported successfully")
        except ImportError as e:
            print(f"   ❌ Failed to import pymongo: {e}")
            print("   💡 Try: pip install pymongo")
            return False
            
        try:
            from passlib.context import CryptContext
            print("   ✅ passlib imported successfully")
        except ImportError as e:
            print(f"   ❌ Failed to import passlib: {e}")
            print("   💡 Try: pip install passlib[bcrypt]")
            return False
        
        # Test MongoDB connection
        print("\n🔗 Testing MongoDB connection...")
        try:
            client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            print("   ✅ MongoDB connection successful!")
        except Exception as e:
            print(f"   ❌ MongoDB connection failed: {e}")
            print("   💡 Please ensure MongoDB is running on localhost:27017")
            print("   💡 Start MongoDB service or check connection settings")
            return False
        
        # Initialize password hashing
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Connect to database
        db = client["PreTectNIDS"]
        users_collection = db["users"]
        
        # Default admin credentials
        admin_username = "admin"
        admin_email = "admin@pretect-nids.com"
        admin_password = "admin123"  # Change this in production!
        admin_role = "admin"  # 使用正确的角色名称，与UserRole.ADMIN一致
        
        print(f"\n👤 Creating admin user: {admin_username}")
        
        # Check if admin already exists
        existing_admin = users_collection.find_one({"username": admin_username})
        if existing_admin:
            print(f"⚠️  Admin account '{admin_username}' already exists!")
            print(f"   Created: {existing_admin.get('created_at', 'Unknown')}")
            print(f"   Email: {existing_admin.get('email', 'Unknown')}")
            
            # Ask if user wants to reset password
            try:
                reset = input("\n🔄 Do you want to reset the admin password? (y/N): ").lower().strip()
                if reset == 'y' or reset == 'yes':
                    # Update password and role
                    hashed_password = pwd_context.hash(admin_password)
                    users_collection.update_one(
                        {"username": admin_username},
                        {"$set": {"password": hashed_password, "role": admin_role}}
                    )
                    print(f"✅ Admin password has been reset to: {admin_password}")
                    print(f"✅ Admin role has been set to: {admin_role}")
                else:
                    print("❌ Operation cancelled.")
            except KeyboardInterrupt:
                print("\n❌ Operation cancelled by user.")
            return True
        
        # Create new admin account
        print("🔨 Creating new admin account...")
        
        hashed_password = pwd_context.hash(admin_password)
        
        admin_doc = {
            "username": admin_username,
            "email": admin_email,
            "password": hashed_password,
            "created_at": get_beijing_time_iso(),
            "is_active": True,
            "is_admin": True,  # Admin flag
            "role": admin_role  # 使用正确的角色名称
        }
        
        result = users_collection.insert_one(admin_doc)
        
        print("✅ Default admin account created successfully!")
        print(f"   Username: {admin_username}")
        print(f"   Email: {admin_email}")
        print(f"   Password: {admin_password}")
        print(f"   MongoDB ID: {result.inserted_id}")
        print(f"   Created: {admin_doc['created_at']}")
        
        print("\n" + "=" * 50)
        print("🔐 IMPORTANT SECURITY NOTICE:")
        print("   Please change the default password after first login!")
        print("   Default credentials are for initial setup only.")
        print("=" * 50)
        
        print("\n🚀 You can now login with:")
        print("   URL: http://localhost:5173/login")
        print("   Username: admin")
        print("   Password: admin123")
        
        return True
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user.")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("   Please check your Python environment and dependencies.")
        return False

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1) 