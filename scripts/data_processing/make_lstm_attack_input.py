import json

# Load DDoS samples
with open('../../samples/ddos_samples.json') as f:
    data = json.load(f)

# Take the first 10 groups
window = data[:10]
# Flatten into a single row
flat = [str(x) for row in window for x in row]
result = ','.join(flat)

# Print to console
print(result)
