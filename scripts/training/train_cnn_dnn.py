import os
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, Dropout, Flatten, Dense, InputLayer
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
import tensorflow as tf
import matplotlib.pyplot as plt

# --- Parameter settings ---
EPOCHS = 50
BATCH_SIZE = 256
RANDOM_SEED = 42
TEST_SIZE = 0.2
VAL_SIZE = 0.2  # from train portion

# --- Path parameters ---
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(ROOT, "dataset", "CICIDS2017 Full dataset.csv")
MODELS_DIR = os.path.join(ROOT, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "cnn_dnn_model.h5")
SCALER_PATH = os.path.join(MODELS_DIR, "cnn_dnn_scaler.pkl")
THRESHOLD_PATH = os.path.join(MODELS_DIR, "cnn_dnn_threshold.txt")
VISUALIZATION_PATH = os.path.join(MODELS_DIR, "cnn_dnn_threshold_curve.png")

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

df[label_col] = df[label_col].astype(str).str.upper().apply(lambda x: 0 if x == "BENIGN" or x == "0" else 1)

# --- Keep numeric features ---
all_num = df.select_dtypes(include=[np.number]).copy()
all_num.replace([np.inf, -np.inf], np.nan, inplace=True)
all_num.fillna(0.0, inplace=True)

# --- Feature / label separation ---
X = all_num.drop(columns=[label_col], errors='ignore')
y = df[label_col].astype(int).to_numpy()

# --- Stratified train/val/test split ---
X_train_full, X_test, y_train_full, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
)
X_train, X_val, y_train, y_val = train_test_split(
    X_train_full, y_train_full, test_size=VAL_SIZE, random_state=RANDOM_SEED, stratify=y_train_full
)

# --- Standardization (fit on train only) ---
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)
os.makedirs(MODELS_DIR, exist_ok=True)
joblib.dump(scaler, SCALER_PATH)

# --- CNN input format conversion: 2D → 3D ---
X_train_cnn = np.expand_dims(X_train_scaled, axis=-1)
X_val_cnn = np.expand_dims(X_val_scaled, axis=-1)
X_test_cnn = np.expand_dims(X_test_scaled, axis=-1)

# --- Compute class weights ---
class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
class_weight_dict = {0: class_weights[0], 1: class_weights[1]}
print(f"📊 Class weights: {class_weight_dict}")

# --- Build CNN + DNN model ---
model = Sequential([
    InputLayer(input_shape=(X_train_cnn.shape[1], 1)),
    Conv1D(64, kernel_size=3, activation='relu'),
    Dropout(0.2),
    Conv1D(32, kernel_size=3, activation='relu'),
    Dropout(0.2),
    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.3),
    Dense(64, activation='relu'),
    Dense(1, activation='sigmoid')  # Binary classification
])

# --- Compile with learning rate scheduling ---
optimizer = Adam(learning_rate=0.001)
model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy'])

# --- Callbacks ---
callbacks = [
    EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True, verbose=1),
    ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-6, verbose=1)
]

# --- Model training ---
print("🚀 Training CNN-DNN classifier...")
history = model.fit(
    X_train_cnn, y_train,
    validation_data=(X_val_cnn, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    class_weight=class_weight_dict,
    callbacks=callbacks,
    verbose=1
)

# --- Model saving ---
model.save(MODEL_PATH)
print("✅ Model saved as cnn_dnn_model.h5")

# --- Convert to TFLite ---
print("⚙️ Converting to TFLite...")
converter = tf.lite.TFLiteConverter.from_keras_model(model)
converter.optimizations = [tf.lite.Optimize.DEFAULT]
tflite_model = converter.convert()
with open(os.path.join(MODELS_DIR, "cnn_dnn_model.tflite"), "wb") as f:
    f.write(tflite_model)

# --- Threshold scanning on validation set ---
print("📐 Scanning threshold on validation set...")
val_prob = model.predict(X_val_cnn, verbose=0).flatten()
best_thr, best_f1 = 0.5, -1.0
thresholds = np.linspace(0.05, 0.95, 181)
f1_scores = []

for thr in thresholds:
    pred = (val_prob >= thr).astype(int)
    f1 = f1_score(y_val, pred, zero_division=0)
    f1_scores.append(f1)
    if f1 > best_f1:
        best_f1, best_thr = f1, float(thr)

print(f"✅ Best threshold (val): {best_thr:.3f} with F1={best_f1:.4f}")

# --- Save threshold ---
with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
    f.write(str(best_thr))

# --- Plot threshold curve ---
plt.figure(figsize=(10, 6))
plt.plot(thresholds, f1_scores, 'b-', linewidth=2)
plt.axvline(best_thr, color='r', linestyle='--', label=f'Best threshold: {best_thr:.3f}')
plt.xlabel('Threshold')
plt.ylabel('F1 Score')
plt.title('CNN-DNN Threshold Optimization')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(VISUALIZATION_PATH)
print(f"📈 Threshold curve saved to {VISUALIZATION_PATH}")

# --- Final test metrics ---
test_prob = model.predict(X_test_cnn, verbose=0).flatten()
test_pred = (test_prob >= best_thr).astype(int)
acc = accuracy_score(y_test, test_pred)
prec = precision_score(y_test, test_pred, zero_division=0)
rec = recall_score(y_test, test_pred, zero_division=0)
f1 = f1_score(y_test, test_pred, zero_division=0)
print(f"📊 Test: acc={acc:.4f} prec={prec:.4f} rec={rec:.4f} f1={f1:.4f} thr={best_thr:.3f}")

print("✅ CNN-DNN model training complete.")
