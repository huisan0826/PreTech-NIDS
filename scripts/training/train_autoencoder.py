import os
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.losses import MeanSquaredError
import tensorflow as tf
import matplotlib.pyplot as plt

# --- Path parameters ---
DATA_PATH = "../../dataset/CICIDS2017 Full dataset.csv"
MODEL_PATH = "../../models/ae_model.h5"
SCALER_PATH = "../../models/ae_scaler.pkl"
THRESHOLD_PATH = "../../models/ae_threshold.txt"
VISUALIZATION_PATH = "../../models/ae_mse_threshold.png"

# 1. Load and clean BENIGN data
print("🔍 Loading BENIGN-only data...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()

label_col = [col for col in df.columns if 'label' in col.lower()]
if not label_col:
    raise Exception("❌ Could not find a column with name 'label'!")
label_col = label_col[0]

df = df[df[label_col] == 'BENIGN']
df = df.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan).dropna()

# 2. Split train and validation sets
X_train, X_val = train_test_split(df, test_size=0.2, random_state=42)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)

# 3. Lightweight Autoencoder network structure
input_dim = X_train_scaled.shape[1]
input_layer = Input(shape=(input_dim,))
encoded = Dense(64, activation='relu')(input_layer)
encoded = Dense(32, activation='relu')(encoded)
encoded = Dense(16, activation='relu')(encoded)
decoded = Dense(32, activation='relu')(encoded)
decoded = Dense(64, activation='relu')(decoded)
decoded = Dense(input_dim, activation='linear')(decoded)

autoencoder = Model(input_layer, decoded)
autoencoder.compile(optimizer='adam', loss=MeanSquaredError())

# 4. Train the model
print("🚀 Training autoencoder...")
autoencoder.fit(
    X_train_scaled, X_train_scaled,
    validation_data=(X_val_scaled, X_val_scaled),
    epochs=20, batch_size=256,
    callbacks=[EarlyStopping(monitor='val_loss', patience=3)]
)

# 5. Save model and scaler
os.makedirs("models", exist_ok=True)
autoencoder.save(MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)

# 6. Quantize and save TFLite model
print("⚙️ Converting to TFLite...")
converter = tf.lite.TFLiteConverter.from_keras_model(autoencoder)
converter.optimizations = [tf.lite.Optimize.DEFAULT]
tflite_model = converter.convert()
with open("models/ae_model.tflite", "wb") as f:
    f.write(tflite_model)
print("✅ TFLite model saved.")

# 7. Plot reconstruction error
print("📊 Evaluating reconstruction error...")
reconstructions = autoencoder.predict(X_val_scaled)
mse = np.mean(np.square(X_val_scaled - reconstructions), axis=1)
threshold = np.percentile(mse, 99.5)

# Save threshold to file for deployment
with open(THRESHOLD_PATH, "w") as f:
    f.write(str(threshold))

plt.hist(mse, bins=50)
plt.axvline(threshold, color='r', label=f'Threshold (99.5%)\n{threshold:.5f}')
plt.title("Reconstruction Error Distribution")
plt.xlabel("MSE")
plt.ylabel("Frequency")
plt.legend()
plt.savefig(VISUALIZATION_PATH)
print(f"📈 Threshold (99.5 percentile): {threshold:.6f}")
print("✅ All done.")
