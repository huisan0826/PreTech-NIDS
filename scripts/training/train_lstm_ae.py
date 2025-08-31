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
DATA_PATH = "../../dataset/CICIDS2017 Full dataset.csv"
MODEL_PATH = "../../models/lstm_ae_model.h5"
SCALER_PATH = "../../models/lstm_ae_scaler.pkl"
THRESHOLD_PATH = "../../models/lstm_ae_threshold.txt"
VISUALIZATION_PATH = "../../models/lstm_ae_mse.png"

# 1. Load and clean BENIGN data
print("🔍 Loading BENIGN-only data...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()  # Remove spaces in column names

if 'Label' not in df.columns:
    raise ValueError("❌ 'Label' column not found in the dataset!")

df = df[df['Label'] == 'BENIGN']
df = df.select_dtypes(include=[np.number])
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# --- Sliding window function ---
def create_sequences(X, timesteps):
    return np.array([X[i:i+timesteps] for i in range(len(X) - timesteps)])

# --- Data splitting and standardization ---
X_train, X_val = train_test_split(df, test_size=0.2, shuffle=False)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
joblib.dump(scaler, SCALER_PATH)

X_train_seq = create_sequences(X_train_scaled, TIMESTEPS)
X_val_seq = create_sequences(X_val_scaled, TIMESTEPS)

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

# --- Reconstruction error evaluation ---
print("📊 Evaluating reconstruction error...")
reconstructions = model.predict(X_val_seq)
mse = np.mean(np.square(X_val_seq - reconstructions), axis=(1, 2))
threshold = np.percentile(mse, 99.5)

# Save threshold to file for deployment
with open(THRESHOLD_PATH, "w") as f:
    f.write(str(threshold))

plt.figure(figsize=(10, 5))
plt.hist(mse, bins=50, alpha=0.7)
plt.axvline(threshold, color='red', linestyle='--', label=f"Threshold: {threshold:.5f}")
plt.title("LSTM Autoencoder Reconstruction Error")
plt.xlabel("MSE")
plt.ylabel("Frequency")
plt.legend()
plt.tight_layout()
plt.savefig(VISUALIZATION_PATH)
print(f"📈 Threshold: {threshold:.6f}")
print("✅ LSTM-AE training complete.")
