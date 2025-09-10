import os
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, BatchNormalization, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.losses import MeanSquaredError
from tensorflow.keras import regularizers
import tensorflow as tf
import matplotlib.pyplot as plt

# --- Path parameters ---
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(ROOT, "dataset", "CICIDS2017 Full dataset.csv")
MODELS_DIR = os.path.join(ROOT, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "ae_model.h5")
SCALER_PATH = os.path.join(MODELS_DIR, "ae_scaler.pkl")
THRESHOLD_PATH = os.path.join(MODELS_DIR, "ae_threshold.txt")
VISUALIZATION_PATH = os.path.join(MODELS_DIR, "ae_mse_threshold.png")

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

# 2. Split train and validation sets
X_train, X_val = train_test_split(benign_clean, test_size=0.2, random_state=42)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)

# --- Prepare attack data for threshold validation ---
X_attack_scaled = scaler.transform(attack_clean)

# 3. Improved Autoencoder network structure for better anomaly detection
input_dim = X_train_scaled.shape[1]
input_layer = Input(shape=(input_dim,))

# Encoder: 77 -> 128 -> 64 -> 32 -> 16
encoded = Dense(128, activation='relu')(input_layer)
encoded = Dropout(0.2)(encoded)
encoded = Dense(64, activation='relu')(encoded)
encoded = Dropout(0.2)(encoded)
encoded = Dense(32, activation='relu')(encoded)
encoded = Dense(16, activation='relu')(encoded)

# Decoder: 16 -> 32 -> 64 -> 128 -> 77
decoded = Dense(32, activation='relu')(encoded)
decoded = Dense(64, activation='relu')(decoded)
decoded = Dropout(0.2)(decoded)
decoded = Dense(128, activation='relu')(decoded)
decoded = Dropout(0.2)(decoded)
decoded = Dense(input_dim, activation='linear')(decoded)

autoencoder = Model(input_layer, decoded)
autoencoder.compile(optimizer='adam', loss=MeanSquaredError())

# 4. Train the model with improved parameters
print("🚀 Training autoencoder...")
checkpoint_path = os.path.join(MODELS_DIR, "ae_model.h5")
callbacks = [
    EarlyStopping(monitor='val_loss', patience=15, restore_best_weights=True, verbose=1),
    ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=8, min_lr=1e-7, verbose=1),
    ModelCheckpoint(filepath=checkpoint_path, monitor='val_loss', save_best_only=True, verbose=1)
]
autoencoder.fit(
    X_train_scaled, X_train_scaled,
    validation_data=(X_val_scaled, X_val_scaled),
    epochs=100, batch_size=512,
    callbacks=callbacks,
    verbose=1
)

# 5. Save model and scaler
os.makedirs(MODELS_DIR, exist_ok=True)
# Ensure best checkpoint persisted as final model
autoencoder.save(MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)

# 6. Quantize and save TFLite model
print("⚙️ Converting to TFLite...")
converter = tf.lite.TFLiteConverter.from_keras_model(autoencoder)
converter.optimizations = [tf.lite.Optimize.DEFAULT]
tflite_model = converter.convert()
with open(os.path.join(MODELS_DIR, "ae_model.tflite"), "wb") as f:
    f.write(tflite_model)
print("✅ TFLite model saved.")

# 7. Enhanced threshold scanning with validation set
print("📊 Evaluating reconstruction error and finding optimal threshold...")

# --- Get reconstruction errors for BENIGN and Attack data ---
benign_reconstructions = autoencoder.predict(X_val_scaled, verbose=0)
benign_mse = np.mean(np.square(X_val_scaled - benign_reconstructions), axis=1)

attack_reconstructions = autoencoder.predict(X_attack_scaled, verbose=0)
attack_mse = np.mean(np.square(X_attack_scaled - attack_reconstructions), axis=1)

# --- Find optimal threshold using F1 score with better range ---
from sklearn.metrics import f1_score, precision_score, recall_score
all_mse = np.concatenate([benign_mse, attack_mse])
all_labels = np.concatenate([np.zeros(len(benign_mse)), np.ones(len(attack_mse))])

# --- Improved threshold selection strategy ---
# Use a wider range and focus on the separation between benign and attack distributions
benign_90th = np.percentile(benign_mse, 90)
benign_99th = np.percentile(benign_mse, 99)
attack_1st = np.percentile(attack_mse, 1)
attack_10th = np.percentile(attack_mse, 10)

# Create threshold range that covers the separation area
min_thr = min(benign_90th, attack_1st)
max_thr = max(benign_99th, attack_10th)
thresholds = np.linspace(min_thr, max_thr, 500)

best_thr, best_f1 = 0.5, -1.0
f1_scores = []
precision_scores = []
recall_scores = []

for thr in thresholds:
    pred = (all_mse >= thr).astype(int)
    f1 = f1_score(all_labels, pred, zero_division=0)
    prec = precision_score(all_labels, pred, zero_division=0)
    rec = recall_score(all_labels, pred, zero_division=0)
    
    f1_scores.append(f1)
    precision_scores.append(prec)
    recall_scores.append(rec)
    
    # Use F1 score as primary metric, but also consider precision-recall balance
    if f1 > best_f1:
        best_f1, best_thr = f1, float(thr)

print(f"✅ Best threshold: {best_thr:.6f} with F1={best_f1:.4f}")

# Save threshold to file for deployment
with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
    f.write(str(best_thr))

# --- Enhanced visualization ---
fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(20, 12))

# Histogram of reconstruction errors
ax1.hist(benign_mse, bins=50, alpha=0.7, label='BENIGN', color='blue', density=True)
ax1.hist(attack_mse, bins=50, alpha=0.7, label='Attack', color='red', density=True)
ax1.axvline(best_thr, color='green', linestyle='--', linewidth=2, label=f'Optimal Threshold: {best_thr:.5f}')
ax1.set_xlabel('Reconstruction Error (MSE)')
ax1.set_ylabel('Density')
ax1.set_title('Reconstruction Error Distribution')
ax1.legend()
ax1.grid(True, alpha=0.3)

# F1 score vs threshold curve
ax2.plot(thresholds, f1_scores, 'b-', linewidth=2, label='F1 Score')
ax2.axvline(best_thr, color='r', linestyle='--', label=f'Best threshold: {best_thr:.5f}')
ax2.set_xlabel('Threshold')
ax2.set_ylabel('F1 Score')
ax2.set_title('F1 Score vs Threshold')
ax2.legend()
ax2.grid(True, alpha=0.3)

# Precision vs threshold curve
ax3.plot(thresholds, precision_scores, 'g-', linewidth=2, label='Precision')
ax3.axvline(best_thr, color='r', linestyle='--', label=f'Best threshold: {best_thr:.5f}')
ax3.set_xlabel('Threshold')
ax3.set_ylabel('Precision')
ax3.set_title('Precision vs Threshold')
ax3.legend()
ax3.grid(True, alpha=0.3)

# Recall vs threshold curve
ax4.plot(thresholds, recall_scores, 'm-', linewidth=2, label='Recall')
ax4.axvline(best_thr, color='r', linestyle='--', label=f'Best threshold: {best_thr:.5f}')
ax4.set_xlabel('Threshold')
ax4.set_ylabel('Recall')
ax4.set_title('Recall vs Threshold')
ax4.legend()
ax4.grid(True, alpha=0.3)

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

print("✅ Autoencoder training complete.")
