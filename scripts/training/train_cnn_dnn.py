import os
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, Dropout, Flatten, Dense, InputLayer
from tensorflow.keras.callbacks import EarlyStopping
import tensorflow as tf

# --- Parameter settings ---
EPOCHS = 10
BATCH_SIZE = 256
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# --- Path parameters ---
DATA_PATH = "../../dataset/CICIDS2017 Full dataset.csv"
MODEL_PATH = "../../models/cnn_dnn_model.h5"
SCALER_PATH = "../../models/cnn_dnn_scaler.pkl"
THRESHOLD_PATH = "../../models/cnn_dnn_threshold.txt"
VISUALIZATION_PATH = "../../models/cnn_dnn_mse_threshold.png"

# 1. Load and clean BENIGN data
print("🔍 Loading BENIGN-only data...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()  # Remove extra spaces in column names

if 'Label' not in df.columns:
    raise ValueError("❌ Column 'Label' not found. Please check the dataset headers.")

# --- Label processing: BENIGN = 0, Attack = 1 ---
df['Label'] = df['Label'].apply(lambda x: 0 if x == "BENIGN" else 1)

# --- Keep numeric features ---
df = df.select_dtypes(include=[np.number])
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# --- Feature / label separation ---
X = df.drop(columns=['Label'], errors='ignore')
y = df['Label']

# --- Standardization ---
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, SCALER_PATH)

# --- CNN input format conversion: 2D → 3D ---
X_cnn = np.expand_dims(X_scaled, axis=-1)

# --- Split training and validation sets ---
X_train, X_val, y_train, y_val = train_test_split(
    X_cnn, y, test_size=0.2, stratify=y, random_state=42
)

# --- Build CNN + DNN model ---
model = Sequential([
    InputLayer(input_shape=(X_train.shape[1], 1)),
    Conv1D(64, kernel_size=3, activation='relu'),
    Dropout(0.2),
    Conv1D(32, kernel_size=3, activation='relu'),
    Flatten(),
    Dense(64, activation='relu'),
    Dense(1, activation='sigmoid')  # Binary classification
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# --- Model training ---
print("🚀 Training CNN-DNN classifier...")
model.fit(
    X_train, y_train,
    validation_data=(X_val, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=[EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)]
)

# --- Model saving ---
model.save(MODEL_PATH)
print("✅ Model saved as cnn_dnn_model.h5")

# --- Convert to TFLite ---
print("⚙️ Converting to TFLite...")
converter = tf.lite.TFLiteConverter.from_keras_model(model)
converter.optimizations = [tf.lite.Optimize.DEFAULT]
tflite_model = converter.convert()
with open(f"{MODEL_DIR}/cnn_dnn_model.tflite", "wb") as f:
    f.write(tflite_model)

print("✅ CNN-DNN model training complete.")
