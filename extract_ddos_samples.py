import pandas as pd
import numpy as np
import json
import os

print("🔍 Loading CICIDS2017 dataset...")
df = pd.read_csv("dataset/CICIDS2017 Full dataset.csv", low_memory=False)
df.columns = df.columns.str.strip()

# Automatically identify label column
label_col = [col for col in df.columns if "label" in col.lower()]
if not label_col:
    raise Exception("❌ 'Label' column not found.")
label_col = label_col[0]

# Filter DDoS attack samples
df_attack = df[df[label_col].fillna('').str.lower().str.contains("ddos")]

# Keep numeric columns, clean invalid values
df_attack = df_attack.select_dtypes(include=[np.number])
df_attack.replace([np.inf, -np.inf], np.nan, inplace=True)
df_attack.dropna(inplace=True)

# Extract first 10 samples
samples = df_attack.head(10).values.tolist()

# Save as JSON file
os.makedirs("samples", exist_ok=True)
with open("samples/ddos_samples.json", "w") as f:
    json.dump(samples, f, indent=2)

print("✅ Saved 10 DDoS samples to samples/ddos_samples.json")
