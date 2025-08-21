import pandas as pd
import json
import os

# --- File paths ---
DATA_PATH = "dataset/CICIDS2017 Full dataset.csv"
OUTPUT_PATH = "sample_BENIGN_features.json"

# --- Load and preprocess ---
print("🔍 Loading and processing dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()

# Check Label column
label_col = [col for col in df.columns if 'label' in col.lower()]
if not label_col:
    raise Exception("❌ Could not find a column with name 'label'!")
label_col = label_col[0]

# Select BENIGN samples + keep only numeric columns
df_benign = df[df[label_col] == "BENIGN"]
df_numeric = df_benign.select_dtypes(include=[float, int])
df_numeric = df_numeric.drop(columns=[label_col], errors='ignore')

# Check column count
if df_numeric.shape[1] != 77:
    raise ValueError(f"❌ Expected 77 features, but got {df_numeric.shape[1]}")

# Extract first 5 rows
samples = df_numeric.head(5).values.tolist()

# Save as JSON for easy copy to Dashboard
with open(OUTPUT_PATH, "w") as f:
    json.dump(samples, f, indent=2)

os.makedirs("samples", exist_ok=True)
with open("samples/BENIGN_samples.json", "w") as f:
    json.dump(samples, f, indent=2)

print(f"✅ Extracted {len(samples)} BENIGN samples with 77 features.")
