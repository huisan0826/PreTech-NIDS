#!/usr/bin/env python3
"""
User Management Script for PreTech-NIDS
This script allows you to manage user accounts in the system.
"""

import sys
from datetime import datetime
from pymongo import MongoClient
from passlib.context import CryptContext

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client["PreTectNIDS"]
users_collection = db["users"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def list_users():
    """List all users in the system"""
    print("\n👥 All Users in PreTech-NIDS:")
    print("=" * 60)
    
    users = users_collection.find({})
    user_count = 0
    
    for user in users:
        user_count += 1
        is_admin = user.get('is_admin', False) or user.get('role') == 'administrator'
        admin_tag = " [ADMIN]" if is_admin else ""
        active_tag = " [INACTIVE]" if not user.get('is_active', True) else ""
        
        print(f"{user_count}. {user['username']}{admin_tag}{active_tag}")
        print(f"   Email: {user['email']}")
        print(f"   Created: {user.get('created_at', 'Unknown')}")
        print(f"   Role: {user.get('role', 'user')}")
        print()
    
    if user_count == 0:
        print("   No users found.")
    else:
        print(f"Total users: {user_count}")

def create_user():
    """Create a new user interactively"""
    print("\n➕ Create New User:")
    print("-" * 30)
    
    try:
        username = input("Username: ").strip()
        if not username:
            print("❌ Username cannot be empty")
            return False
            
        # Check if user exists
        if users_collection.find_one({"username": username}):
            print(f"❌ User '{username}' already exists")
            return False
            
        email = input("Email: ").strip()
        if not email:
            print("❌ Email cannot be empty")
            return False
            
        # Check if email exists
        if users_collection.find_one({"email": email}):
            print(f"❌ Email '{email}' already exists")
            return False
            
        password = input("Password: ").strip()
        if not password:
            print("❌ Password cannot be empty")
            return False
            
        is_admin = input("Is admin? (y/N): ").lower().strip() == 'y'
        
        # Create user document
        hashed_password = pwd_context.hash(password)
        
        user_doc = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "created_at": datetime.utcnow().isoformat(),
            "is_active": True,
            "is_admin": is_admin,
            "role": "administrator" if is_admin else "user"
        }
        
        result = users_collection.insert_one(user_doc)
        
        print(f"\n✅ User '{username}' created successfully!")
        print(f"   MongoDB ID: {result.inserted_id}")
        print(f"   Role: {'Administrator' if is_admin else 'User'}")
        
        return True
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled.")
        return False

def delete_user():
    """Delete a user"""
    print("\n🗑️  Delete User:")
    print("-" * 20)
    
    try:
        username = input("Username to delete: ").strip()
        if not username:
            print("❌ Username cannot be empty")
            return False
            
        user = users_collection.find_one({"username": username})
        if not user:
            print(f"❌ User '{username}' not found")
            return False
            
        # Show user info
        print(f"\nUser to delete:")
        print(f"   Username: {user['username']}")
        print(f"   Email: {user['email']}")
        print(f"   Created: {user.get('created_at', 'Unknown')}")
        print(f"   Admin: {user.get('is_admin', False)}")
        
        confirm = input(f"\n⚠️  Are you sure you want to delete '{username}'? (yes/N): ").lower().strip()
        if confirm != 'yes':
            print("❌ Operation cancelled.")
            return False
            
        users_collection.delete_one({"username": username})
        print(f"✅ User '{username}' deleted successfully!")
        
        return True
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled.")
        return False

def reset_password():
    """Reset user password"""
    print("\n🔐 Reset User Password:")
    print("-" * 25)
    
    try:
        username = input("Username: ").strip()
        if not username:
            print("❌ Username cannot be empty")
            return False
            
        user = users_collection.find_one({"username": username})
        if not user:
            print(f"❌ User '{username}' not found")
            return False
            
        new_password = input("New password: ").strip()
        if not new_password:
            print("❌ Password cannot be empty")
            return False
            
        # Update password
        hashed_password = pwd_context.hash(new_password)
        users_collection.update_one(
            {"username": username},
            {"$set": {"password": hashed_password}}
        )
        
        print(f"✅ Password for '{username}' reset successfully!")
        
        return True
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled.")
        return False

def main():
    """Main menu"""
    print("🛡️ PreTech-NIDS User Management")
    print("=" * 40)
    
    try:
        # Test MongoDB connection
        client.admin.command('ping')
        print("✅ MongoDB connection successful!")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        print("   Please ensure MongoDB is running on localhost:27017")
        sys.exit(1)
    
    while True:
        print("\n📋 Main Menu:")
        print("1. List all users")
        print("2. Create new user") 
        print("3. Delete user")
        print("4. Reset password")
        print("5. Exit")
        
        try:
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == '1':
                list_users()
            elif choice == '2':
                create_user()
            elif choice == '3':
                delete_user()
            elif choice == '4':
                reset_password()
            elif choice == '5':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid option. Please select 1-5.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main() 