import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, RepeatVector, TimeDistributed, Dense
from tensorflow.keras.callbacks import EarlyStopping
import tensorflow as tf

# --- Parameter settings ---
TIMESTEPS = 10
BATCH_SIZE = 256
EPOCHS = 20
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# --- Path parameters ---
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(ROOT, "dataset", "CICIDS2017 Full dataset.csv")
MODELS_DIR = os.path.join(ROOT, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "lstm_ae_model.h5")
SCALER_PATH = os.path.join(MODELS_DIR, "lstm_ae_scaler.pkl")
THRESHOLD_PATH = os.path.join(MODELS_DIR, "lstm_ae_threshold.txt")
VISUALIZATION_PATH = os.path.join(MODELS_DIR, "lstm_ae_mse.png")

# 1. Load and clean data
print("🔍 Loading dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()

# --- Label detection and processing ---
label_col = None
for c in ["Label", "label", " Attack ", "Attack", "attack"]:
    if c.strip() in df.columns:
        label_col = c.strip()
        break
if label_col is None:
    raise RuntimeError("Label column not found. Please ensure 'Label' exists in CSV.")

# --- Separate BENIGN and Attack data ---
df[label_col] = df[label_col].astype(str).str.upper()
benign_data = df[df[label_col] == 'BENIGN'].copy()
attack_data = df[df[label_col] != 'BENIGN'].copy()

# --- Process BENIGN data for training ---
benign_clean = benign_data.select_dtypes(include=[np.number]).copy()
benign_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
benign_clean.fillna(0.0, inplace=True)

# --- Process Attack data for validation ---
attack_clean = attack_data.select_dtypes(include=[np.number]).copy()
attack_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
attack_clean.fillna(0.0, inplace=True)

# --- Sliding window function ---
def create_sequences(X, timesteps):
    return np.array([X[i:i+timesteps] for i in range(len(X) - timesteps)])

# --- Data splitting and standardization ---
X_train, X_val = train_test_split(benign_clean, test_size=0.2, shuffle=False, random_state=42)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_attack_scaled = scaler.transform(attack_clean)
os.makedirs(MODELS_DIR, exist_ok=True)
joblib.dump(scaler, SCALER_PATH)

X_train_seq = create_sequences(X_train_scaled, TIMESTEPS)
X_val_seq = create_sequences(X_val_scaled, TIMESTEPS)
X_attack_seq = create_sequences(X_attack_scaled, TIMESTEPS)

# --- Build LSTM Autoencoder ---
model = Sequential([
    LSTM(128, activation='relu', input_shape=(TIMESTEPS, X_train_seq.shape[2]), return_sequences=False),
    RepeatVector(TIMESTEPS),
    LSTM(128, activation='relu', return_sequences=True),
    TimeDistributed(Dense(X_train_seq.shape[2]))
])

# ✅ Use function object instead of 'mse' string
model.compile(optimizer='adam', loss=tf.keras.losses.MeanSquaredError())

# --- Model training ---
print("🚀 Training LSTM Autoencoder...")
model.fit(
    X_train_seq, X_train_seq,
    validation_data=(X_val_seq, X_val_seq),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=[EarlyStopping(monitor='val_loss', patience=3)]
)

model.save(MODEL_PATH)
print("✅ Model saved to lstm_ae_model.h5")

# --- TFLite conversion ---
print("⚙️ Converting to TFLite with SELECT_TF_OPS support...")
converter = tf.lite.TFLiteConverter.from_keras_model(model)
converter.target_spec.supported_ops = [
    tf.lite.OpsSet.TFLITE_BUILTINS,
    tf.lite.OpsSet.SELECT_TF_OPS
]
converter._experimental_lower_tensor_list_ops = False
converter.optimizations = [tf.lite.Optimize.DEFAULT]

try:
    tflite_model = converter.convert()
    with open(f"{MODEL_DIR}/lstm_ae_model.tflite", "wb") as f:
        f.write(tflite_model)
    print("✅ TFLite model saved to lstm_ae_model.tflite")
except Exception as e:
    print(f"❌ TFLite conversion failed: {e}")

# --- Enhanced reconstruction error evaluation with threshold optimization ---
print("📊 Evaluating reconstruction error and finding optimal threshold...")

# --- Get reconstruction errors for BENIGN and Attack data ---
benign_reconstructions = model.predict(X_val_seq, verbose=0)
benign_mse = np.mean(np.square(X_val_seq - benign_reconstructions), axis=(1, 2))

attack_reconstructions = model.predict(X_attack_seq, verbose=0)
attack_mse = np.mean(np.square(X_attack_seq - attack_reconstructions), axis=(1, 2))

# --- Find optimal threshold using F1 score ---
from sklearn.metrics import f1_score, precision_score, recall_score
all_mse = np.concatenate([benign_mse, attack_mse])
all_labels = np.concatenate([np.zeros(len(benign_mse)), np.ones(len(attack_mse))])

# --- Scan thresholds ---
thresholds = np.linspace(np.percentile(all_mse, 1), np.percentile(all_mse, 99), 100)
best_thr, best_f1 = 0.5, -1.0
f1_scores = []

for thr in thresholds:
    pred = (all_mse >= thr).astype(int)
    f1 = f1_score(all_labels, pred, zero_division=0)
    f1_scores.append(f1)
    if f1 > best_f1:
        best_f1, best_thr = f1, float(thr)

print(f"✅ Best threshold: {best_thr:.6f} with F1={best_f1:.4f}")

# Save threshold to file for deployment
with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
    f.write(str(best_thr))

# --- Enhanced visualization ---
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

# Histogram of reconstruction errors
ax1.hist(benign_mse, bins=50, alpha=0.7, label='BENIGN', color='blue')
ax1.hist(attack_mse, bins=50, alpha=0.7, label='Attack', color='red')
ax1.axvline(best_thr, color='green', linestyle='--', linewidth=2, label=f'Optimal Threshold: {best_thr:.5f}')
ax1.set_xlabel('Reconstruction Error (MSE)')
ax1.set_ylabel('Frequency')
ax1.set_title('LSTM Autoencoder Reconstruction Error')
ax1.legend()
ax1.grid(True, alpha=0.3)

# F1 score vs threshold curve
ax2.plot(thresholds, f1_scores, 'b-', linewidth=2)
ax2.axvline(best_thr, color='r', linestyle='--', label=f'Best threshold: {best_thr:.5f}')
ax2.set_xlabel('Threshold')
ax2.set_ylabel('F1 Score')
ax2.set_title('LSTM-AE Threshold Optimization')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig(VISUALIZATION_PATH)
print(f"📈 Enhanced visualization saved to {VISUALIZATION_PATH}")

# --- Final metrics ---
final_pred = (all_mse >= best_thr).astype(int)
acc = np.mean(final_pred == all_labels)
prec = precision_score(all_labels, final_pred, zero_division=0)
rec = recall_score(all_labels, final_pred, zero_division=0)
f1 = f1_score(all_labels, final_pred, zero_division=0)
print(f"📊 Final metrics: acc={acc:.4f} prec={prec:.4f} rec={rec:.4f} f1={f1:.4f}")

print("✅ LSTM-AE training complete.")
