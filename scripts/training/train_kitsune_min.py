import os
import sys
import glob
import argparse
import math
import joblib


def discover_pcaps(pcap_dir: str, recursive: bool) -> list:
    pattern = os.path.join(pcap_dir, "**", "*.pcap") if recursive else os.path.join(pcap_dir, "*.pcap")
    files = glob.glob(pattern, recursive=recursive)
    files = [f for f in files if os.path.isfile(f)]
    return sorted(files)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train KitNET (Kitsune) from PCAPs without hardcoding.")
    parser.add_argument("--pcap", action="append", default=None, help="Explicit PCAP file path (can be repeated, order preserved).")
    parser.add_argument("--pcap-dir", type=str, required=False, default=None, help="Directory containing PCAP files (will be scanned if --pcap not provided).")
    parser.add_argument("--recursive", action="store_true", help="Recursively search for PCAP files.")
    parser.add_argument("--limit-per-file", type=int, default=20000, help="Max feature vectors to read per PCAP file.")
    parser.add_argument("--max-total", type=int, default=100000, help="Max total feature vectors across all files.")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Fraction for training; remainder used for validation.")
    parser.add_argument("--threshold-method", type=str, choices=["fpr", "percentile"], default="fpr", help="How to determine anomaly threshold from validation scores.")
    parser.add_argument("--target-fpr", type=float, default=0.01, help="Target false positive rate on validation when method=fpr.")
    parser.add_argument("--percentile", type=float, default=95.0, help="Percentile for threshold when method=percentile.")
    parser.add_argument("--fm-grace", type=int, default=5000, help="Feature mapping grace period (KitNET param).")
    parser.add_argument("--ad-grace", type=int, default=50000, help="Anomaly detection grace period (KitNET param).")
    parser.add_argument("--max-autoencoders", type=int, default=None, help="Max number of autoencoders in ensemble (KitNET param).")
    return parser.parse_args()


def main() -> None:
    # Resolve project root and ensure Kitsune modules are importable
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sys.path.extend([
        os.path.join(root, "kitsune"),
        os.path.join(root, "kitsune", "KitNET"),
    ])

    # Lazy imports after sys.path setup
    from FeatureExtractor import FE as FeatureExtractor  # type: ignore
    from KitNET.KitNET import KitNET  # type: ignore

    args = parse_args()

    pcap_files = [
        "E:\\Monday-WorkingHours.pcap",
        "E:\\Tuesday-WorkingHours.pcap",
        "E:\\Wednesday-workingHours.pcap",
        "E:\\Thursday-WorkingHours.pcap",
        "E:\\Friday-WorkingHours.pcap",
    ]
    missing = [p for p in pcap_files if not os.path.isfile(p)]
    if missing:
        raise FileNotFoundError(f"Missing required PCAP files on E: {missing}")
    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found under: {args.pcap_dir}")
    print(f"Found {len(pcap_files)} PCAP files")

    # Extract features from PCAPs
    features = []
    total_packets_processed = 0
    for pcap_file in pcap_files:
        if len(features) >= args.max_total:
            break
        print(f"Processing {pcap_file}...")
        try:
            feature_extractor = FeatureExtractor(pcap_file, limit=args.limit_per_file)
            file_features = []
            while len(file_features) < args.limit_per_file and len(features) + len(file_features) < args.max_total:
                feature_vector = feature_extractor.get_next_vector()
                if feature_vector is None:
                    break
                file_features.append(feature_vector)
                total_packets_processed += 1
            features.extend(file_features)
            print(f"Extracted {len(file_features)} features from {os.path.basename(pcap_file)}")
        except Exception as e:
            print(f"Warning: Failed to process {pcap_file}: {e}")
            continue

    if not features:
        raise RuntimeError(
            "No features extracted from PCAP files. Ensure the files are readable and dependencies are installed."
        )

    print(f"✅ Successfully extracted {len(features)} features from {total_packets_processed} packets across {len(pcap_files)} files")

    input_dim = len(features[0])
    print(f"🔧 Initializing KitNET with input dimension: {input_dim}")
    kitnet = KitNET(n=input_dim, maxAE=args.max_autoencoders, fm_grace=args.fm_grace, ad_grace=args.ad_grace)

    # Split into train/val by stream order (unsupervised)
    train_end = int(len(features) * args.train_ratio)
    train_stream = features[:train_end]
    val_stream = features[train_end:]
    print(f"Train stream: {len(train_stream)}, Val stream: {len(val_stream)}")

    # Unsupervised learning phase on training stream
    print("🚀 Starting unsupervised training on training stream...")
    for i, row in enumerate(train_stream):
        if i % 10000 == 0 and i > 0:
            print(f"Processed {i}/{len(train_stream)} features...")
        kitnet.process(row)

    print(f"✅ Training completed on {len(train_stream)} feature vectors")

    # Score validation stream
    print("📏 Scoring validation stream to derive threshold...")
    val_scores = []
    for row in val_stream:
        score = float(kitnet.execute(row))
        val_scores.append(score)

    if not val_scores:
        raise RuntimeError("Validation stream is empty; adjust --train-ratio or provide more data.")

    import numpy as np
    scores = np.asarray(val_scores, dtype=float)

    if args.threshold_method == "fpr":
        # Assume validation stream mostly benign; target FPR defines threshold at (1 - target_fpr) quantile
        q = max(0.0, min(1.0, 1.0 - float(args.target_fpr)))
        thr = float(np.quantile(scores, q))
        print(f"Selected threshold by target FPR {args.target_fpr:.4f}: quantile {q:.4f} -> {thr:.6f}")
    else:
        # percentile method
        p = max(0.0, min(100.0, float(args.percentile)))
        thr = float(np.percentile(scores, p))
        print(f"Selected threshold by percentile {p:.2f}% -> {thr:.6f}")

    # Persist model & threshold
    models_dir = os.path.join(root, "models")
    os.makedirs(models_dir, exist_ok=True)
    out_model = os.path.join(models_dir, "kitsune_model.pkl")
    out_thr = os.path.join(models_dir, "kitsune_threshold.txt")
    joblib.dump(kitnet, out_model)
    with open(out_thr, "w", encoding="utf-8") as f:
        f.write(str(thr))
    print(f"💾 Saved Kitsune model: {out_model}")
    print(f"💾 Saved learned threshold: {out_thr} (value={thr:.6f})")


if __name__ == "__main__":
    main()


