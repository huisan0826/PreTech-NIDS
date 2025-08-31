import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

# --- Path parameters ---
DATA_PATH = "../../dataset/CICIDS2017 Full dataset.csv"
MODEL_PATH = "../../models/rf_model.pkl"
SCALER_PATH = "../../models/rf_scaler.pkl"
IMPORTANCE_PNG = "../../models/rf_feature_importance.png"

# --- Training parameters (optimized) ---
MAX_SAMPLES = 150000
MAX_SYNTH = 50000
N_ESTIMATORS = 100
RANDOM_SEED = 42

print("🔍 Loading BENIGN-only data...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()

# --- Label encoding (Attack=1, BENIGN=0) ---
df['Label'] = df['Label'].apply(lambda x: 0 if x == "BENIGN" else 1)

# --- Numeric cleaning ---
df = df.select_dtypes(include=[np.number])
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Debug: Check actual feature count
print(f"🔍 Actual numeric features count: {len(df.columns)}")
print(f"🔍 Features: {df.columns.tolist()[:5]} ... {df.columns.tolist()[-5:]}")

# --- Limit sample size ---
df = df.sample(n=min(len(df), MAX_SAMPLES), random_state=RANDOM_SEED)

# --- Feature and label split ---
X = df.drop(columns=['Label'])
y = df['Label']

# --- Feature scaling ---
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, SCALER_PATH)

# --- Synthesize attack samples ---
X_benign = pd.DataFrame(X_scaled[y == 0], columns=X.columns)
X_attack = pd.DataFrame(X_scaled[y == 1], columns=X.columns)

synth_size = min(len(X_attack), MAX_SYNTH)
print(f"📊 Synthesizing {synth_size} fake attack samples...")

synth_samples = X_attack.sample(n=synth_size, replace=True, random_state=RANDOM_SEED)
X_train = pd.concat([X_benign, synth_samples], ignore_index=True)
y_train = np.concatenate([np.zeros(len(X_benign)), np.ones(len(synth_samples))])

# --- Train model ---
print("🚀 Training Random Forest classifier...")
os.makedirs("models", exist_ok=True)
clf = RandomForestClassifier(n_estimators=N_ESTIMATORS, n_jobs=-1, random_state=RANDOM_SEED, oob_score=True)
clf.fit(X_train, y_train)
joblib.dump(clf, MODEL_PATH)
print(f"✅ Model saved to {MODEL_PATH}")

# --- Feature importance visualization ---
print("📈 Saving feature importance plot...")
importances = pd.Series(clf.feature_importances_, index=X.columns)
importances.sort_values(ascending=False).head(20).plot(kind='barh', figsize=(10,6))
plt.title("Top 20 Feature Importances (Random Forest)")
plt.tight_layout()
plt.savefig(IMPORTANCE_PNG)
print(f"🖼️ Feature importance saved to {IMPORTANCE_PNG}")
