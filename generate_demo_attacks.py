#!/usr/bin/env python3
"""
Demo Attack Data Generator for Alert System Testing (trigger alerts via /predict)
"""
import requests
import random
import time
from datetime import datetime, timedelta

# Supported models
MODELS = ['kitsune', 'autoencoder', 'lstm', 'cnn', 'rf']

def generate_attack_features():
    # Generate a set of features likely to be classified as Attack
    # Dataset has 77 numeric features (79 total columns - 1 label column - 1 non-numeric column)
    return [random.uniform(8, 15) for _ in range(77)]

def send_attack_to_predict(model=None):
    if model is None:
        model = random.choice(MODELS)
    features = generate_attack_features()
    data = {
        "features": features,
        "model": model
    }
    try:
        resp = requests.post("http://localhost:8000/predict", json=data, timeout=10)
        if resp.status_code == 200:
            result = resp.json()
            if result.get("prediction") == "Attack" or result.get("prediction") == 1:
                print(f"✅ Attack triggered! Model: {model}, Result: {result}")
                return True
            else:
                print(f"⚠️ Not detected as attack. Model: {model}, Result: {result}")
        else:
            print(f"❌ HTTP error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"❌ Network error: {e}")
    return False

def generate_demo_attacks(count=10, delay=1):
    print(f"🚀 Generating {count} demo attacks via /predict...")
    success = 0
    for i in range(count):
        if send_attack_to_predict():
            success += 1
        time.sleep(delay)
    print(f"🏁 Done! {success}/{count} attacks triggered.")

def generate_attack_burst(duration_minutes=5):
    print(f"💥 Generating attack burst for {duration_minutes} minutes...")
    start = datetime.now()
    end = start + timedelta(minutes=duration_minutes)
    total = 0
    while datetime.now() < end:
        n = random.randint(1, 3)
        for _ in range(n):
            if send_attack_to_predict():
                total += 1
        delay = random.uniform(2, 8)
        print(f"⏳ {n} attacks sent, waiting {delay:.1f}s...")
        time.sleep(delay)
    print(f"🏁 Burst done! Total attacks: {total}")

def check_api_status():
    # Check if the backend API is running
    try:
        resp = requests.get("http://localhost:8000/", timeout=5)
        if resp.status_code == 200:
            print("✅ Backend API is running")
            return True
    except Exception as e:
        print(f"❌ Cannot connect to backend: {e}")
    return False

def main():
    print("🛡️  PreTech-NIDS Alert Demo Data Generator (/predict)")
    print("=" * 50)
    if not check_api_status():
        print("❌ Please ensure backend is running on http://localhost:8000/")
        return
    while True:
        print("\n📋 Choose an option:")
        print("1. Generate 10 demo attacks (quick test)")
        print("2. Generate 25 demo attacks (standard demo)")
        print("3. Generate 50 demo attacks (comprehensive demo)")
        print("4. Generate attack burst (5 minutes)")
        print("5. Generate attack burst (10 minutes)")
        print("6. Custom attack generation")
        print("7. Exit")
        try:
            choice = input("\nEnter your choice (1-7): ").strip()
            if choice == '1':
                generate_demo_attacks(count=10, delay=1)
            elif choice == '2':
                generate_demo_attacks(count=25, delay=2)
            elif choice == '3':
                generate_demo_attacks(count=50, delay=1.5)
            elif choice == '4':
                generate_attack_burst(duration_minutes=5)
            elif choice == '5':
                generate_attack_burst(duration_minutes=10)
            elif choice == '6':
                count = int(input("Enter number of attacks: "))
                delay = float(input("Enter delay between attacks (seconds): "))
                generate_demo_attacks(count=count, delay=delay)
            elif choice == '7':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please try again.")
        except (ValueError, KeyboardInterrupt):
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == '__main__':
    main() 