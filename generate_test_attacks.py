#!/usr/bin/env python3
"""
Generate test attack scenarios with different severities
Used to verify alert level assignment (Low/Medium/High/Critical)
Now includes global IP simulation for attack map visualization
"""

import subprocess
import time
import random
from scapy.all import *
import threading

# Global IP addresses for different regions
GLOBAL_IPS = {
    'US_WEST': [
        '8.8.8.8', '1.1.1.1', '208.67.222.222',  # DNS servers
        '104.16.132.229', '104.16.133.229',      # Cloudflare
        '52.84.0.0', '52.85.0.0',               # AWS US West
        '35.160.0.0', '35.161.0.0',             # AWS US West 2
    ],
    'US_EAST': [
        '8.8.4.4', '1.0.0.1', '208.67.220.220',  # DNS servers
        '52.0.0.0', '52.1.0.0',                 # AWS US East
        '34.192.0.0', '34.193.0.0',             # AWS US East 1
        '54.80.0.0', '54.81.0.0',               # AWS US East 1
    ],
    'EUROPE': [
        '1.1.1.1', '8.8.8.8',                   # Global DNS
        '52.16.0.0', '52.17.0.0',               # AWS EU West 1
        '34.240.0.0', '34.241.0.0',             # AWS EU West 1
        '54.76.0.0', '54.77.0.0',               # AWS EU West 1
    ],
    'ASIA': [
        '8.8.8.8', '1.1.1.1',                   # Global DNS
        '52.78.0.0', '52.79.0.0',               # AWS Asia Pacific
        '54.169.0.0', '54.170.0.0',             # AWS Asia Pacific
        '13.112.0.0', '13.113.0.0',             # AWS Asia Pacific
    ],
    'CHINA': [
        '114.114.114.114', '223.5.5.5',         # Chinese DNS
        '119.29.29.29', '180.76.76.76',         # Chinese DNS
        '202.96.134.133', '202.96.209.133',     # Chinese DNS
    ],
    'RUSSIA': [
        '77.88.8.8', '77.88.8.1',               # Yandex DNS
        '8.8.8.8', '1.1.1.1',                   # Global DNS
    ],
    'BRAZIL': [
        '8.8.8.8', '1.1.1.1',                   # Global DNS
        '54.94.0.0', '54.95.0.0',               # AWS South America
    ],
    'AUSTRALIA': [
        '8.8.8.8', '1.1.1.1',                   # Global DNS
        '54.66.0.0', '54.67.0.0',               # AWS Asia Pacific
    ],
    'LOCAL': [
        '192.168.1.100', '192.168.1.101',       # Local network
        '10.0.0.100', '10.0.0.101',             # Local network
        '172.16.0.100', '172.16.0.101',         # Local network
    ]
}

def get_random_source_ip(region=None):
    """Get a random source IP from specified region"""
    if region is None:
        region = random.choice(list(GLOBAL_IPS.keys()))
    
    return random.choice(GLOBAL_IPS[region])

def create_attack_packet(src_ip, dst_ip, dport, attack_type="SYN"):
    """Create attack packet with specified source IP"""
    if attack_type == "SYN":
        return IP(src=src_ip, dst=dst_ip)/TCP(dport=dport, flags="S")
    elif attack_type == "UDP":
        return IP(src=src_ip, dst=dst_ip)/UDP(dport=dport)
    elif attack_type == "ICMP":
        return IP(src=src_ip, dst=dst_ip)/ICMP()
    else:
        return IP(src=src_ip, dst=dst_ip)/TCP(dport=dport, flags="S")

def generate_low_severity_attacks(target_ip="192.168.216.131"):
    """Low-severity activity - should produce MEDIUM/LOW alerts"""
    print("🔍 Generating low-severity activity...")
    
    # 1) Port scan from different regions
    print("  - Port scan (few ports) from multiple regions")
    regions = ['US_WEST', 'EUROPE', 'ASIA']
    for region in regions:
        src_ip = get_random_source_ip(region)
        print(f"    From {region}: {src_ip}")
        for port in [80, 443, 22, 21, 23]:
            packet = create_attack_packet(src_ip, target_ip, port, "SYN")
            send(packet, verbose=0)
            time.sleep(0.1)
    
    # 2) Mostly normal traffic with occasional anomalies
    print("  - Mixed normal traffic with minor anomalies")
    for i in range(5):
        src_ip = get_random_source_ip('US_EAST')
        # Normal HTTP-like SYNs
        packet = create_attack_packet(src_ip, target_ip, 80, "SYN")
        send(packet, verbose=0)
        time.sleep(0.2)
        
        # A few anomalous packets
        if i % 2 == 0:
            packet = create_attack_packet(src_ip, target_ip, random.randint(1000, 2000), "SYN")
            send(packet, verbose=0)

def generate_medium_severity_attacks(target_ip="192.168.216.131"):
    """Medium-severity activity - should produce HIGH/MEDIUM alerts"""
    print("⚠️ Generating medium-severity activity...")
    
    # 1) Medium-scale port scan from multiple regions
    print("  - Medium-scale port scan from multiple regions")
    regions = ['US_WEST', 'US_EAST', 'EUROPE', 'ASIA']
    for region in regions:
        src_ip = get_random_source_ip(region)
        print(f"    From {region}: {src_ip}")
        for port in range(80, 120, 5):  # Scan more ports
            packet = create_attack_packet(src_ip, target_ip, port, "SYN")
            send(packet, verbose=0)
            time.sleep(0.05)
    
    # 2) SSH brute-force attempts from different countries
    print("  - SSH brute-force attempts from different countries")
    countries = ['CHINA', 'RUSSIA', 'BRAZIL']
    for country in countries:
        src_ip = get_random_source_ip(country)
        print(f"    From {country}: {src_ip}")
        for i in range(5):
            packet = create_attack_packet(src_ip, target_ip, 22, "SYN")
            send(packet, verbose=0)
            time.sleep(0.1)
    
    # 3) Access to risky service ports
    print("  - Access to risky service ports")
    src_ip = get_random_source_ip('AUSTRALIA')
    print(f"    From AUSTRALIA: {src_ip}")
    for port in [8080, 8180, 8009]:  # Access to risky service ports
        packet = create_attack_packet(src_ip, target_ip, port, "SYN")
        send(packet, verbose=0)
        time.sleep(0.1)

def generate_high_severity_attacks(target_ip="192.168.216.131"):
    """High-severity activity - should produce HIGH alerts"""
    print("🚨 Generating high-severity activity...")
    
    # 1) Large-scale port scan from multiple regions
    print("  - Large-scale port scan from multiple regions")
    regions = ['US_WEST', 'US_EAST', 'EUROPE', 'ASIA', 'CHINA', 'RUSSIA']
    for region in regions:
        src_ip = get_random_source_ip(region)
        print(f"    From {region}: {src_ip}")
        for port in range(1, 100, 10):  # Scan a large number of ports
            packet = create_attack_packet(src_ip, target_ip, port, "SYN")
            send(packet, verbose=0)
            time.sleep(0.01)
    
    # 2) SYN flood pattern from different sources
    print("  - SYN flood pattern from different sources")
    flood_sources = ['US_WEST', 'EUROPE', 'ASIA']
    for region in flood_sources:
        src_ip = get_random_source_ip(region)
        print(f"    SYN flood from {region}: {src_ip}")
        for i in range(20):
            packet = create_attack_packet(src_ip, target_ip, 80, "SYN")
            send(packet, verbose=0)
            time.sleep(0.01)
    
    # 3) Probe high-risk ports from various countries
    print("  - Probing high-risk ports from various countries")
    high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 3389, 8080, 8180]
    countries = ['CHINA', 'RUSSIA', 'BRAZIL', 'AUSTRALIA']
    for country in countries:
        src_ip = get_random_source_ip(country)
        print(f"    High-risk probing from {country}: {src_ip}")
        for port in high_risk_ports:
            packet = create_attack_packet(src_ip, target_ip, port, "SYN")
            send(packet, verbose=0)
            time.sleep(0.05)

def generate_critical_severity_attacks(target_ip="192.168.216.131"):
    """Critical-severity activity - should produce CRITICAL alerts"""
    print("💀 Generating critical-severity activity...")
    
    # 1) Zero-day like behavior from multiple regions
    print("  - Zero-day behavior simulation from multiple regions")
    regions = ['US_WEST', 'US_EAST', 'EUROPE', 'ASIA', 'CHINA', 'RUSSIA']
    for region in regions:
        src_ip = get_random_source_ip(region)
        print(f"    Zero-day simulation from {region}: {src_ip}")
        for i in range(5):
            # Craft unusually large payload
            payload = "A" * 1000 + "B" * 1000
            packet = IP(src=src_ip, dst=target_ip)/TCP(dport=80, flags="S")/Raw(load=payload)
            send(packet, verbose=0)
            time.sleep(0.01)
    
    # 2) Large-volume DDoS-like burst from multiple sources
    print("  - Large-volume DDoS simulation from multiple sources")
    ddos_sources = ['US_WEST', 'EUROPE', 'ASIA', 'CHINA', 'RUSSIA', 'BRAZIL']
    for region in ddos_sources:
        src_ip = get_random_source_ip(region)
        print(f"    DDoS from {region}: {src_ip}")
        for i in range(20):
            packet = create_attack_packet(src_ip, target_ip, 80, "SYN")
            send(packet, verbose=0)
            time.sleep(0.001)
    
    # 3) Multi-target probing from various countries
    print("  - Multi-target probing from various countries")
    targets = [target_ip, "192.168.216.129", "192.168.216.130"]
    countries = ['CHINA', 'RUSSIA', 'BRAZIL', 'AUSTRALIA', 'US_WEST', 'EUROPE']
    for country in countries:
        src_ip = get_random_source_ip(country)
        print(f"    Multi-target probing from {country}: {src_ip}")
        for target in targets:
            for port in [80, 443, 22, 21]:
                packet = create_attack_packet(src_ip, target, port, "SYN")
                send(packet, verbose=0)
                time.sleep(0.01)

def main():
    print("🎯 Global Attack Scenario Generator")
    print("=" * 50)
    print("🌍 Now simulates attacks from multiple global regions!")
    print("📍 Attacks will appear on the attack map with real locations")
    print("=" * 50)
    
    target_ip = input("Target IP (default: 192.168.216.131): ").strip()
    if not target_ip:
        target_ip = "192.168.216.131"
    
    print(f"\nTarget IP: {target_ip}")
    print("\nSelect severity to simulate:")
    print("1. Low severity (expect MEDIUM/LOW alerts) - US, Europe, Asia")
    print("2. Medium severity (expect HIGH/MEDIUM alerts) - Multiple regions")
    print("3. High severity (expect HIGH alerts) - Global attack")
    print("4. Critical severity (expect CRITICAL alerts) - Worldwide DDoS")
    print("5. Run all (execute 1→4 in order)")
    print("6. Global demo (quick test from all regions)")
    
    choice = input("\nChoose (1-6): ").strip()
    
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
    elif choice == "6":
        print("\n🌍 Running global demo...")
        print("  - Quick attacks from all regions")
        all_regions = list(GLOBAL_IPS.keys())
        for region in all_regions:
            if region != 'LOCAL':  # Skip local network for global demo
                src_ip = get_random_source_ip(region)
                print(f"    Attack from {region}: {src_ip}")
                for port in [80, 443, 22]:
                    packet = create_attack_packet(src_ip, target_ip, port, "SYN")
                    send(packet, verbose=0)
                    time.sleep(0.1)
    else:
        print("❌ Invalid choice")
        return
    
    print(f"\n✅ Test completed! Check the attack map for global visualization.")
    print("🌍 Attacks should now appear on the map with different colors and regions!")

if __name__ == "__main__":
    main()
