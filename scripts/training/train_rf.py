import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
import matplotlib.pyplot as plt

# --- Path parameters ---
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(ROOT, "dataset", "CICIDS2017 Full dataset.csv")
MODELS_DIR = os.path.join(ROOT, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "rf_scaler.pkl")
THRESHOLD_PATH = os.path.join(MODELS_DIR, "rf_threshold.txt")
IMPORTANCE_PNG = os.path.join(MODELS_DIR, "rf_feature_importance.png")

# --- Training parameters (optimized) ---
MAX_SAMPLES = 300000
RANDOM_SEED = 42
TEST_SIZE = 0.2
VAL_SIZE = 0.2  # from train portion

print("🔍 Loading dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)
df.columns = df.columns.str.strip()

# --- Label encoding (Attack=1, BENIGN=0) ---
label_col = None
for c in ["Label", "label", " Attack ", "Attack", "attack"]:
    if c.strip() in df.columns:
        label_col = c.strip()
        break
if label_col is None:
    raise RuntimeError("Label column not found. Please ensure 'Label' exists in CSV.")
df[label_col] = df[label_col].astype(str).str.upper().apply(lambda x: 0 if x == "BENIGN" or x == "0" else 1)

# --- Numeric cleaning ---
all_num = df.select_dtypes(include=[np.number]).copy()
all_num.replace([np.inf, -np.inf], np.nan, inplace=True)
all_num.fillna(0.0, inplace=True)

# Debug: Check actual feature count
print(f"🔍 Actual numeric features count: {len(all_num.columns)}")
print(f"🔍 Features: {all_num.columns.tolist()[:5]} ... {all_num.columns.tolist()[-5:]}")

# --- Limit sample size ---
df_lim = df.sample(n=min(len(df), MAX_SAMPLES), random_state=RANDOM_SEED)

# --- Feature and label split ---
X = all_num.loc[df_lim.index].drop(columns=[label_col], errors='ignore')
y = df_lim[label_col].astype(int).to_numpy()

X_train_full, X_test, y_train_full, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
)

# split train into train/val
X_train, X_val, y_train, y_val = train_test_split(
    X_train_full, y_train_full, test_size=VAL_SIZE, random_state=RANDOM_SEED, stratify=y_train_full
)

# --- Feature scaling (fit on train only) ---
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)
os.makedirs(MODELS_DIR, exist_ok=True)
joblib.dump(scaler, SCALER_PATH)

# --- Model with class weights & fast grid search ---
print("🔧 Searching best Random Forest hyperparameters (fast CV)...")
base = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=RANDOM_SEED,
                              class_weight="balanced")
param_grid = {
    "n_estimators": [100, 200],
    "max_depth": [None, 20],
    "min_samples_leaf": [1, 2],
    "max_features": ["sqrt", "log2"],
}
search = GridSearchCV(base, param_grid, scoring="f1", n_jobs=-1, cv=2, verbose=1)
search.fit(X_train_scaled, y_train)
clf = search.best_estimator_
print(f"✅ Best params: {search.best_params_}")

# --- Train model ---
print("📐 Scanning threshold on validation set...")
val_prob = clf.predict_proba(X_val_scaled)[:, 1]
best_thr, best_f1 = 0.5, -1.0
for thr in np.linspace(0.05, 0.95, 181):
    pred = (val_prob >= thr).astype(int)
    f1 = f1_score(y_val, pred, zero_division=0)
    if f1 > best_f1:
        best_f1, best_thr = f1, float(thr)
print(f"✅ Best threshold (val): {best_thr:.3f} with F1={best_f1:.4f}")
with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
    f.write(str(best_thr))

# Save final model
joblib.dump(clf, MODEL_PATH)
print(f"✅ Model & threshold saved to {MODEL_PATH} and {THRESHOLD_PATH}")

# --- Feature importance visualization ---
print("📈 Saving feature importance plot...")
importances = pd.Series(clf.feature_importances_, index=X_train.columns if hasattr(X_train, 'columns') else np.arange(X_train_scaled.shape[1]))
importances.sort_values(ascending=False).head(20).plot(kind='barh', figsize=(10,6))
plt.title("Top 20 Feature Importances (Random Forest)")
plt.tight_layout()
plt.savefig(IMPORTANCE_PNG)
print(f"🖼️ Feature importance saved to {IMPORTANCE_PNG}")

# --- Final test metrics ---
test_prob = clf.predict_proba(X_test_scaled)[:, 1]
test_pred = (test_prob >= best_thr).astype(int)
acc = accuracy_score(y_test, test_pred)
prec = precision_score(y_test, test_pred, zero_division=0)
rec = recall_score(y_test, test_pred, zero_division=0)
f1 = f1_score(y_test, test_pred, zero_division=0)
print(f"📊 Test: acc={acc:.4f} prec={prec:.4f} rec={rec:.4f} f1={f1:.4f} thr={best_thr:.3f}") 