import sys
import os
import joblib

# Add kitsune directory to path (now in root directory)
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "kitsune"))

from Kitsune import Kitsune

# Read pcap file
pcap_path = os.path.join("data", "example.pcap")

# Initialize Kitsune model (using default parameters)
K = Kitsune(pcap_path, 5000, 5000, 10)

print("🧪 Running Kitsune on:", pcap_path)

i = 0
while True:
    score = K.proc_next_packet()
    if score == -1:
        break
    print(f"Packet {i+1}: Anomaly Score = {score:.5f}")
    i += 1

print(f"✅ Done. Total packets processed: {i}")

# Save model
joblib.dump(K.AnomDetector, "models/kitsune_model.pkl")
print("✅ Kitsune model saved at models/kitsune_model.pkl")
