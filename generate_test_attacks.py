#!/usr/bin/env python3
"""
Generate test attack scenarios with different severities
Used to verify alert level assignment (Low/Medium/High/Critical)
"""

import subprocess
import time
import random
from scapy.all import *
import threading

def generate_low_severity_attacks(target_ip="192.168.216.131"):
    """Low-severity activity - should produce MEDIUM/LOW alerts"""
    print("🔍 Generating low-severity activity...")
    
    # 1) Port scan - small number of ports
    print("  - Port scan (few ports)")
    for port in [80, 443, 22, 21, 23]:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.1)
    
    # 2) Mostly normal traffic with occasional anomalies
    print("  - Mixed normal traffic with minor anomalies")
    for i in range(5):
        # Normal HTTP-like SYNs
        packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
        send(packet, verbose=0)
        time.sleep(0.2)
        
        # A few anomalous packets
        if i % 2 == 0:
            packet = IP(dst=target_ip)/TCP(dport=random.randint(1000, 2000), flags="S")
            send(packet, verbose=0)

def generate_medium_severity_attacks(target_ip="192.168.216.131"):
    """Medium-severity activity - should produce HIGH/MEDIUM alerts"""
    print("⚠️ Generating medium-severity activity...")
    
    # 1) Medium-scale port scan
    print("  - Medium-scale port scan")
    for port in range(80, 120, 5):  # Scan more ports
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.05)
    
    # 2) SSH brute-force attempts
    print("  - SSH brute-force attempts")
    for i in range(10):
        packet = IP(dst=target_ip)/TCP(dport=22, flags="S")
        send(packet, verbose=0)
        time.sleep(0.1)
    
    # 3) Access to risky service ports
    print("  - Access to risky service ports")
    for port in [8080, 8180, 8009]:  # Access to risky service ports
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.1)

def generate_high_severity_attacks(target_ip="192.168.216.131"):
    """High-severity activity - should produce HIGH alerts"""
    print("🚨 Generating high-severity activity...")
    
    # 1) Large-scale port scan
    print("  - Large-scale port scan")
    for port in range(1, 1000, 10):  # Scan a large number of ports
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.01)
    
    # 2) SYN flood pattern
    print("  - SYN flood pattern")
    for i in range(50):
        packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
        send(packet, verbose=0)
        time.sleep(0.01)
    
    # 3) Probe high-risk ports
    print("  - Probing high-risk ports")
    high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 3389, 8080, 8180]
    for port in high_risk_ports:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.05)

def generate_critical_severity_attacks(target_ip="192.168.216.131"):
    """Critical-severity activity - should produce CRITICAL alerts"""
    print("💀 Generating critical-severity activity...")
    
    # 1) Zero-day like behavior - unusual payload
    print("  - Zero-day behavior simulation")
    for i in range(20):
        # Craft unusually large payload
        payload = "A" * 1000 + "B" * 1000
        packet = IP(dst=target_ip)/TCP(dport=80, flags="S")/Raw(load=payload)
        send(packet, verbose=0)
        time.sleep(0.01)
    
    # 2) Large-volume DDoS-like burst
    print("  - Large-volume DDoS simulation")
    for i in range(100):
        packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
        send(packet, verbose=0)
        time.sleep(0.001)
    
    # 3) Multi-target probing
    print("  - Multi-target probing")
    targets = [target_ip, "192.168.216.129", "192.168.216.130"]
    for target in targets:
        for port in [80, 443, 22, 21]:
            packet = IP(dst=target)/TCP(dport=port, flags="S")
            send(packet, verbose=0)
            time.sleep(0.01)

def main():
    print("🎯 Attack Scenario Generator")
    print("=" * 50)
    
    target_ip = input("Target IP (default: 192.168.216.131): ").strip()
    if not target_ip:
        target_ip = "192.168.216.131"
    
    print(f"\nTarget IP: {target_ip}")
    print("\nSelect severity to simulate:")
    print("1. Low severity (expect MEDIUM/LOW alerts)")
    print("2. Medium severity (expect HIGH/MEDIUM alerts)")
    print("3. High severity (expect HIGH alerts)")
    print("4. Critical severity (expect CRITICAL alerts)")
    print("5. Run all (execute 1→4 in order)")
    
    choice = input("\nChoose (1-5): ").strip()
    
    if choice == "1":
        generate_low_severity_attacks(target_ip)
    elif choice == "2":
        generate_medium_severity_attacks(target_ip)
    elif choice == "3":
        generate_high_severity_attacks(target_ip)
    elif choice == "4":
        generate_critical_severity_attacks(target_ip)
    elif choice == "5":
        print("\n🔄 Running all scenarios...")
        generate_low_severity_attacks(target_ip)
        time.sleep(2)
        generate_medium_severity_attacks(target_ip)
        time.sleep(2)
        generate_high_severity_attacks(target_ip)
        time.sleep(2)
        generate_critical_severity_attacks(target_ip)
    else:
        print("❌ Invalid choice")
        return
    
    print(f"\n✅ Test completed! Check the alert system for different levels.")

if __name__ == "__main__":
    main()
