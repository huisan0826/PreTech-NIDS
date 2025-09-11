import os
import sys
import json
import warnings
from typing import Dict, List, Tuple, Optional

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, precision_recall_curve, roc_auc_score, auc
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODELS_DIR = os.path.join(ROOT, "models")
DATA_CSV = os.path.join(ROOT, "dataset", "CICIDS2017 Full dataset.csv")


def detect_label_column(df: pd.DataFrame) -> Tuple[str, np.ndarray]:
    candidates = [
        "Label",
        "label",
        "Attack",
        "attack",
        "is_attack",
        "target",
    ]
    # normalize name lookup: strip spaces and lowercase
    norm_map = {c.strip().lower(): c for c in df.columns}
    for col in candidates:
        key = col.strip().lower()
        if key in norm_map:
            orig = norm_map[key]
            y_raw = df[orig]
            if y_raw.dtype == object:
                y = y_raw.astype(str).str.upper().map(lambda v: 0 if "BENIGN" in v or v == "0" else 1)
            else:
                y = (y_raw.astype(float) > 0).astype(int)
            return orig, y.to_numpy()
    # fallback: no label, assume zeros
    return "(none)", np.zeros(len(df), dtype=int)


def extract_numeric_features(df: pd.DataFrame, max_dim: int) -> np.ndarray:
    num_df = df.select_dtypes(include=[np.number]).copy()
    # remove obviously non-feature columns if present
    for drop_col in ["Flow ID", "Timestamp", "ProtocolName", "Source IP", "Destination IP"]:
        if drop_col in num_df.columns:
            num_df.drop(columns=[drop_col], inplace=True)
    X = num_df.to_numpy(dtype=float, copy=False)
    if X.shape[1] >= max_dim:
        X = X[:, :max_dim]
    else:
        pad = np.zeros((X.shape[0], max_dim - X.shape[1]), dtype=float)
        X = np.concatenate([X, pad], axis=1)
    X[np.isnan(X)] = 0.0
    X[np.isinf(X)] = 0.0
    return X


def load_threshold(path: str, default_val: float) -> float:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return float(f.read().strip())
    except Exception:
        return default_val


def evaluate_metrics(y_true: np.ndarray, y_prob: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, auc

    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    try:
        out["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        # Calculate PR AUC using precision_recall_curve and auc
        from sklearn.metrics import precision_recall_curve
        precision, recall, _ = precision_recall_curve(y_true, y_prob)
        out["pr_auc"] = float(auc(recall, precision))
    except Exception:
        pass
    return out


def plot_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, model_name: str, save_path: str):
    """绘制混淆矩阵"""
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['BENIGN', 'Attack'], 
                yticklabels=['BENIGN', 'Attack'])
    plt.title(f'{model_name.upper()} Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_roc_pr_curves(y_true: np.ndarray, y_prob: np.ndarray, model_name: str, save_dir: str):
    """绘制ROC和PR曲线"""
    # ROC Curve
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = roc_auc_score(y_true, y_prob)
    
    # PR Curve
    precision, recall, _ = precision_recall_curve(y_true, y_prob)
    pr_auc = auc(recall, precision)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # ROC
    ax1.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    ax1.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    ax1.set_xlim([0.0, 1.0])
    ax1.set_ylim([0.0, 1.05])
    ax1.set_xlabel('False Positive Rate')
    ax1.set_ylabel('True Positive Rate')
    ax1.set_title(f'{model_name.upper()} ROC Curve')
    ax1.legend(loc="lower right")
    ax1.grid(True, alpha=0.3)
    
    # PR
    ax2.plot(recall, precision, color='darkorange', lw=2, label=f'PR curve (AUC = {pr_auc:.3f})')
    ax2.set_xlim([0.0, 1.0])
    ax2.set_ylim([0.0, 1.05])
    ax2.set_xlabel('Recall')
    ax2.set_ylabel('Precision')
    ax2.set_title(f'{model_name.upper()} Precision-Recall Curve')
    ax2.legend(loc="lower left")
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, f'{model_name}_curves.png'), dpi=300, bbox_inches='tight')
    plt.close()


def plot_class_distribution(y_true: np.ndarray, model_name: str, save_path: str):
    """绘制类别分布"""
    unique, counts = np.unique(y_true, return_counts=True)
    labels = ['BENIGN', 'Attack']
    colors = ['skyblue', 'lightcoral']
    
    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, counts, color=colors, alpha=0.7)
    plt.title(f'{model_name.upper()} Class Distribution')
    plt.ylabel('Count')
    
    # 添加数值标签
    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01,
                f'{count:,}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()


def evaluate_rf(X: np.ndarray, y: np.ndarray, save_plots: bool = True) -> Dict[str, float]:
    import joblib

    model_path = os.path.join(MODELS_DIR, "rf_model.pkl")
    scaler_path = os.path.join(MODELS_DIR, "rf_scaler.pkl")
    threshold_path = os.path.join(MODELS_DIR, "rf_threshold.txt")
    
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        return {}
    
    rf = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    threshold = load_threshold(threshold_path, 0.5)
    
    Xs = scaler.transform(X)
    prob = rf.predict_proba(Xs)[:, 1]
    pred = (prob >= threshold).astype(int)
    
    if save_plots:
        plots_dir = os.path.join(MODELS_DIR, "evaluation_plots")
        os.makedirs(plots_dir, exist_ok=True)
        plot_confusion_matrix(y, pred, "rf", os.path.join(plots_dir, "rf_confusion.png"))
        plot_roc_pr_curves(y, prob, "rf", plots_dir)
        plot_class_distribution(y, "rf", os.path.join(plots_dir, "rf_distribution.png"))
    
    metrics = evaluate_metrics(y, prob, pred)
    # Persist chosen threshold for deployment
    try:
        with open(os.path.join(MODELS_DIR, "rf_threshold.txt"), "w", encoding="utf-8") as f:
            f.write(str(threshold))
    except Exception as e:
        print(f"[RF] Failed to write threshold: {e}")
    return metrics


def evaluate_autoencoder_like(X: np.ndarray, y: np.ndarray, model_name: str, save_plots: bool = True) -> Dict[str, float]:
    # model_name in {"ae", "lstm_ae", "cnn_dnn"}
    try:
        import joblib
        import tensorflow as tf
        from tensorflow import keras  # noqa: F401  (ensures keras available)
    except Exception as e:
        print(f"[{model_name.upper()}] Import error: {e}")
        return {}

    def paths(prefix: str):
        return (
            os.path.join(MODELS_DIR, f"{prefix}_model.h5"),
            os.path.join(MODELS_DIR, f"{prefix}_scaler.pkl"),
        )

    if model_name == "ae":
        model_path, scaler_path = paths("ae")
        thr = load_threshold(os.path.join(MODELS_DIR, "ae_threshold.txt"), 1.0)
        if not (os.path.exists(model_path) and os.path.exists(scaler_path)):
            return {}
        model = tf.keras.models.load_model(model_path)
        scaler = joblib.load(scaler_path)
        Xs = scaler.transform(X)
        recon = model.predict(Xs, verbose=0)
        mse = np.mean((Xs - recon) ** 2, axis=1)
        pred = (mse > thr).astype(int)
        # map mse to [0,1] by rank as pseudo-prob for ROC
        prob = (mse - mse.min()) / (mse.ptp() + 1e-9)
        
        if save_plots:
            plots_dir = os.path.join(MODELS_DIR, "evaluation_plots")
            os.makedirs(plots_dir, exist_ok=True)
            plot_confusion_matrix(y, pred, "ae", os.path.join(plots_dir, "ae_confusion.png"))
            plot_roc_pr_curves(y, prob, "ae", plots_dir)
            plot_class_distribution(y, "ae", os.path.join(plots_dir, "ae_distribution.png"))
        
        metrics = evaluate_metrics(y, prob, pred)
        # persist threshold for deployment
        try:
            with open(os.path.join(MODELS_DIR, "ae_threshold.txt"), "w", encoding="utf-8") as f:
                f.write(str(thr))
        except Exception as e:
            print(f"[AE] Failed to write threshold: {e}")
        return metrics

    if model_name == "lstm":
        model_path = os.path.join(MODELS_DIR, "lstm_model.h5")
        scaler_path = os.path.join(MODELS_DIR, "lstm_scaler.pkl")
        thr = load_threshold(os.path.join(MODELS_DIR, "lstm_threshold.txt"), 0.5)
        if not (os.path.exists(model_path) and os.path.exists(scaler_path)):
            print(f"[LSTM] Model or scaler not found: {model_path}, {scaler_path}")
            return {}
        try:
            model = tf.keras.models.load_model(model_path)
            scaler = joblib.load(scaler_path)
            print(f"[LSTM] Model loaded successfully, scaler expects {scaler.n_features_in_} features")
        except Exception as e:
            print(f"[LSTM] Error loading model: {e}")
            return {}
        
        # Create sequences for LSTM classifier
        def create_sequences_lstm(X, timesteps=10):
            Xs = []
            for i in range(len(X) - timesteps + 1):
                Xs.append(X[i:i+timesteps])
            return np.array(Xs)
        
        try:
            Xs = scaler.transform(X)
            print(f"[LSTM] Scaled data shape: {Xs.shape}")
            Xseq = create_sequences_lstm(Xs, 10)
            print(f"[LSTM] Sequence data shape: {Xseq.shape}")
            
            # For sequences shorter than timesteps, pad with zeros
            if len(X) < 10:
                pad_width = 10 - len(X)
                Xs_padded = np.pad(Xs, ((0, pad_width), (0, 0)), mode='constant', constant_values=0)
                Xseq = create_sequences_lstm(Xs_padded, 10)
            
            prob = model.predict(Xseq, verbose=0).flatten()
            pred = (prob >= thr).astype(int)
            print(f"[LSTM] Predictions shape: {pred.shape}, threshold: {thr}")
        except Exception as e:
            print(f"[LSTM] Error during prediction: {e}")
            return 
        
        # Adjust predictions to match original length
        if len(pred) > len(y):
            pred = pred[:len(y)]
            prob = prob[:len(y)]
        elif len(pred) < len(y):
            # Pad with benign predictions for missing timesteps
            pad_len = len(y) - len(pred)
            pred = np.concatenate([pred, np.zeros(pad_len, dtype=int)])
            prob = np.concatenate([prob, np.zeros(pad_len)])
        
        if save_plots:
            plots_dir = os.path.join(MODELS_DIR, "evaluation_plots")
            os.makedirs(plots_dir, exist_ok=True)
            plot_confusion_matrix(y, pred, "lstm", os.path.join(plots_dir, "lstm_confusion.png"))
            plot_roc_pr_curves(y, prob, "lstm", plots_dir)
            plot_class_distribution(y, "lstm", os.path.join(plots_dir, "lstm_distribution.png"))
        
        metrics = evaluate_metrics(y, prob, pred)
        try:
            with open(os.path.join(MODELS_DIR, "lstm_threshold.txt"), "w", encoding="utf-8") as f:
                f.write(str(thr))
        except Exception as e:
            print(f"[LSTM] Failed to write threshold: {e}")
        return metrics

    if model_name == "cnn_dnn":
        model_path, scaler_path = paths("cnn_dnn")
        threshold_path = os.path.join(MODELS_DIR, "cnn_dnn_threshold.txt")
        if not (os.path.exists(model_path) and os.path.exists(scaler_path)):
            return {}
        model = tf.keras.models.load_model(model_path)
        scaler = joblib.load(scaler_path)
        threshold = load_threshold(threshold_path, 0.5)
        
        Xs = scaler.transform(X)
        Xin = np.expand_dims(Xs, axis=-1)
        prob = model.predict(Xin, verbose=0).reshape(-1)
        pred = (prob >= threshold).astype(int)
        
        if save_plots:
            plots_dir = os.path.join(MODELS_DIR, "evaluation_plots")
            os.makedirs(plots_dir, exist_ok=True)
            plot_confusion_matrix(y, pred, "cnn_dnn", os.path.join(plots_dir, "cnn_dnn_confusion.png"))
            plot_roc_pr_curves(y, prob, "cnn_dnn", plots_dir)
            plot_class_distribution(y, "cnn_dnn", os.path.join(plots_dir, "cnn_dnn_distribution.png"))
        
        metrics = evaluate_metrics(y, prob, pred)
        try:
            with open(os.path.join(MODELS_DIR, "cnn_dnn_threshold.txt"), "w", encoding="utf-8") as f:
                f.write(str(threshold))
        except Exception as e:
            print(f"[CNN_DNN] Failed to write threshold: {e}")
        return metrics

    return {}


def evaluate_kitsune(X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
    # Kitsune expects 100-dim features; we'll zero-pad if needed
    model_path = os.path.join(MODELS_DIR, "kitsune_model.pkl")
    if not os.path.exists(model_path):
        print(f"[KITSUNE] Skip: model not found at {model_path}")
        return {}
    try:
        # Ensure KitNET dependency is discoverable during unpickling
        kitsune_root = os.path.join(ROOT, "kitsune")
        kitnet_dir = os.path.join(kitsune_root, "KitNET")
        for p in [kitsune_root, kitnet_dir]:
            if p not in sys.path:
                sys.path.append(p)

        import joblib, pickle
        # Robust load: try joblib, then pickle with latin1 if needed
        try:
            k = joblib.load(model_path)
        except Exception as e1:
            print(f"[KITSUNE] joblib load failed: {e1}; trying pickle...")
            try:
                with open(model_path, 'rb') as f:
                    k = pickle.load(f)
            except Exception as e2:
                print(f"[KITSUNE] pickle default failed: {e2}; trying latin1...")
                with open(model_path, 'rb') as f:
                    k = pickle.load(f, encoding='latin1')
        Xk = X
        if Xk.shape[1] < 100:
            pad = np.zeros((Xk.shape[0], 100 - Xk.shape[1]), dtype=float)
            Xk = np.concatenate([Xk, pad], axis=1)
        Xk = Xk[:, :100]
        scores = []
        for row in Xk:
            scores.append(float(k.execute(row)))
        scores = np.asarray(scores)
        # Heuristic threshold by 95th percentile on benign (y==0) subset if available
        if np.any(y == 0):
            thr = float(np.percentile(scores[y == 0], 95))
        else:
            thr = float(np.percentile(scores, 95))
        pred = (scores > thr).astype(int)
        prob = (scores - scores.min()) / (scores.ptp() + 1e-9)
        metrics = evaluate_metrics(y, prob, pred)
        # also persist selected threshold
        try:
            with open(os.path.join(MODELS_DIR, "kitsune_threshold.txt"), "w", encoding="utf-8") as f:
                f.write(str(thr))
        except Exception as e:
            print(f"[KITSUNE] Failed to write threshold: {e}")
        return metrics
    except Exception as e:
        print(f"[KITSUNE] Skip due to error: {e}")
        return {}


def main() -> None:
    if not os.path.exists(DATA_CSV):
        raise FileNotFoundError(f"Dataset CSV not found: {DATA_CSV}")
    print(f"Loading dataset: {DATA_CSV}")
    df = pd.read_csv(DATA_CSV, low_memory=False)
    label_col, y = detect_label_column(df)
    print(f"Detected label column: {label_col}")

    # Use 77-dim features baseline (matches API code)，并做分层拆分
    X = extract_numeric_features(df.drop(columns=[c for c in [label_col] if c in df.columns]), 77)

    # Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")
    print(f"Class distribution - Train: {np.bincount(y_train)}, Test: {np.bincount(y_test)}")

    results: Dict[str, Dict[str, float]] = {}

    # RF
    print("\n🔍 Evaluating Random Forest...")
    r = evaluate_rf(X_test, y_test)
    if r:
        results["rf"] = r

    # AE / LSTM / CNN-DNN
    for name in ["ae", "lstm", "cnn_dnn"]:
        print(f"\n🔍 Evaluating {name.upper()}...")
        r = evaluate_autoencoder_like(X_test, y_test, name)
        if r:
            results[name] = r

    # Kitsune
    print("\n🔍 Evaluating KITSUNE...")
    r = evaluate_kitsune(X_test, y_test)
    if r:
        results["kitsune"] = r

    if not results:
        print("No models evaluated (models missing or dependencies unavailable).")
        return

    print("\n" + "="*60)
    print("EVALUATION SUMMARY (Test Set)")
    print("="*60)
    
    # Create summary table
    summary_data = []
    for model_name, metrics in results.items():
        summary_data.append({
            'Model': model_name.upper(),
            'Accuracy': f"{metrics.get('accuracy', 0):.4f}",
            'Precision': f"{metrics.get('precision', 0):.4f}",
            'Recall': f"{metrics.get('recall', 0):.4f}",
            'F1-Score': f"{metrics.get('f1', 0):.4f}",
            'ROC-AUC': f"{metrics.get('roc_auc', 0):.4f}",
            'PR-AUC': f"{metrics.get('pr_auc', 0):.4f}"
        })
    
    summary_df = pd.DataFrame(summary_data)
    print(summary_df.to_string(index=False))
    
    # Check for models achieving 95%+ accuracy
    high_performers = []
    for model_name, metrics in results.items():
        if metrics.get('accuracy', 0) >= 0.95:
            high_performers.append(model_name)
    
    if high_performers:
        print(f"\n🎉 Models achieving ≥95% accuracy: {', '.join(high_performers)}")
    else:
        print(f"\n⚠️  No models achieved ≥95% accuracy. Consider retraining with optimized parameters.")

    # Save detailed JSON
    out_path = os.path.join(MODELS_DIR, "evaluation_summary.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n📊 Detailed metrics saved to: {out_path}")
    
    # Save summary CSV
    csv_path = os.path.join(MODELS_DIR, "evaluation_summary.csv")
    summary_df.to_csv(csv_path, index=False)
    print(f"📈 Summary table saved to: {csv_path}")
    
    print(f"\n📁 All evaluation plots saved to: {os.path.join(MODELS_DIR, 'evaluation_plots')}")


if __name__ == "__main__":
    main()


