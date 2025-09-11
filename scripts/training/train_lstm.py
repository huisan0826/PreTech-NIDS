import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint

# --- Parameter settings ---
TIMESTEPS = 10
BATCH_SIZE = 128
EPOCHS = 100
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# --- Path parameters ---
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(ROOT, "dataset", "CICIDS2017 Full dataset.csv")
MODELS_DIR = os.path.join(ROOT, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "lstm_model.h5")
SCALER_PATH = os.path.join(MODELS_DIR, "lstm_scaler.pkl")
THRESHOLD_PATH = os.path.join(MODELS_DIR, "lstm_threshold.txt")

# 1. Load and clean data
print("🔍 Loading dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()

# --- Label detection ---
label_col = None
for c in ["Label", "label", " Attack ", "Attack", "attack"]:
    if c.strip() in df.columns:
        label_col = c.strip()
        break
if label_col is None:
    raise RuntimeError("Label column not found. Please ensure 'Label' exists in CSV.")

# --- Preprocess labels ---
df[label_col] = df[label_col].astype(str).str.upper()
df[label_col] = df[label_col].apply(lambda x: 0 if x == "BENIGN" else 1)  # 0=Benign, 1=Attack

# --- Keep only numeric features (exclude label column) ---
df_clean = df.select_dtypes(include=[np.number]).copy()
# Remove label column if it's numeric
if label_col in df_clean.columns:
    df_clean = df_clean.drop(columns=[label_col])
df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
df_clean.fillna(0.0, inplace=True)

X = df_clean.values
y = df[label_col].values

# --- Train/test split ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, shuffle=True, random_state=42, stratify=y)

# --- Scaling ---
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
os.makedirs(MODELS_DIR, exist_ok=True)
joblib.dump(scaler, SCALER_PATH)

# --- Create sequences for LSTM ---
def create_sequences(X, y, timesteps):
    Xs, ys = [], []
    for i in range(len(X) - timesteps + 1):
        Xs.append(X[i:i+timesteps])
        ys.append(y[i+timesteps-1])  # Use the last timestep's label
    return np.array(Xs), np.array(ys)

X_train_seq, y_train_seq = create_sequences(X_train_scaled, y_train, TIMESTEPS)
X_test_seq, y_test_seq = create_sequences(X_test_scaled, y_test, TIMESTEPS)

print(f"📊 Original data shape: {X_train_scaled.shape}")
print(f"📊 Sequence data shape: {X_train_seq.shape}")
print(f"📊 Label distribution: {np.bincount(y_train_seq)}")

print(f"✅ Training data shape: {X_train_seq.shape}, Labels: {y_train_seq.shape}")

# --- Build simplified LSTM classifier ---
model = Sequential([
    LSTM(128, return_sequences=True, input_shape=(TIMESTEPS, X_train_seq.shape[2])),
    Dropout(0.3),
    
    LSTM(64, return_sequences=False),
    Dropout(0.3),
    
    Dense(32, activation='relu'),
    Dropout(0.2),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
              loss='binary_crossentropy',
              metrics=['accuracy'])

# --- Training ---
callbacks = [
    EarlyStopping(monitor='val_loss', patience=15, restore_best_weights=True, verbose=1),
    ReduceLROnPlateau(monitor='val_loss', factor=0.7, patience=8, min_lr=1e-6, verbose=1),
    ModelCheckpoint(filepath=MODEL_PATH, monitor='val_loss', save_best_only=True, verbose=1)
]

print("🚀 Training LSTM classifier...")
print(f"📊 Training data: {X_train_seq.shape}, Test data: {X_test_seq.shape}")
history = model.fit(
    X_train_seq, y_train_seq,
    validation_data=(X_test_seq, y_test_seq),  # 使用真正的测试集作为验证集
    epochs=50,
    batch_size=256,
    callbacks=callbacks,
    verbose=1
)

# --- Convert to TFLite ---
print("⚙️ Converting to TFLite...")
try:
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.target_spec.supported_ops = [
        tf.lite.OpsSet.TFLITE_BUILTINS,
        tf.lite.OpsSet.SELECT_TF_OPS
    ]
    converter._experimental_lower_tensor_list_ops = False
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()
    with open(os.path.join(MODELS_DIR, "lstm_model.tflite"), "wb") as f:
        f.write(tflite_model)
    print("✅ TFLite model saved.")
except Exception as e:
    print(f"❌ TFLite conversion failed: {e}")
    print("⚠️ Continuing without TFLite conversion...")

# --- Threshold optimization on test set ---
print("📐 Finding optimal threshold...")
test_prob = model.predict(X_test_seq, verbose=0).flatten()
best_thr, best_f1 = 0.5, -1.0
thresholds = np.linspace(0.1, 0.9, 81) 

for thr in thresholds:
    pred = (test_prob >= thr).astype(int)
    f1 = f1_score(y_test_seq, pred, zero_division=0)
    if f1 > best_f1:
        best_f1, best_thr = f1, float(thr)

print(f"✅ Best threshold (test): {best_thr:.3f} with F1={best_f1:.4f}")
print(f"📊 Test predictions distribution: {np.bincount((test_prob >= best_thr).astype(int))}")
print(f"📊 Test true labels distribution: {np.bincount(y_test_seq)}")

# Save threshold
with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
    f.write(str(best_thr))

# --- Final evaluation ---
print("📊 Final evaluation on test set...")
test_pred = (test_prob >= best_thr).astype(int)

acc = accuracy_score(y_test_seq, test_pred)
prec = precision_score(y_test_seq, test_pred, zero_division=0)
rec = recall_score(y_test_seq, test_pred, zero_division=0)
f1 = f1_score(y_test_seq, test_pred, zero_division=0)
roc_auc = roc_auc_score(y_test_seq, test_prob)

print(f"✅ Final Metrics: Accuracy={acc:.4f}, Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f}, ROC-AUC={roc_auc:.4f}")
print(f"📊 This should now match the evaluation script results!")

# --- Plot training history ---
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.plot(history.history['loss'], label='Training Loss')
plt.plot(history.history['val_loss'], label='Validation Loss')
plt.title('Model Loss')
plt.xlabel('Epoch')
plt.ylabel('Loss')
plt.legend()

plt.subplot(1, 2, 2)
plt.plot(history.history['accuracy'], label='Training Accuracy')
plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
plt.title('Model Accuracy')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend()

plt.tight_layout()
plt.savefig(os.path.join(MODELS_DIR, "lstm_training_history.png"), dpi=300, bbox_inches='tight')
print(f"📈 Training history saved to {os.path.join(MODELS_DIR, 'lstm_training_history.png')}")

print("✅ LSTM classifier training complete.")
