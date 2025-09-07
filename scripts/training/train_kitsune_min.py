import os
import sys
import joblib


def main() -> None:
    # Resolve project root and ensure Kitsune modules are importable
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sys.path.extend([
        os.path.join(root, "kitsune"),
        os.path.join(root, "kitsune", "KitNET"),
    ])

    # Lazy imports after sys.path setup
    from FeatureExtractor import FeatureExtractor  # type: ignore
    from KitNET import KitNET  # type: ignore

    # Use the example PCAP bundled in the repo for a minimal unsupervised training
    pcap_path = os.path.join(root, "data", "example.pcap")
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(
            f"PCAP not found: {pcap_path}. Please place a pcap file at this path."
        )

    # Extract a limited number of packets to keep training fast and deterministic
    # This is intended to produce a model artifact compatible with runtime deps
    feature_extractor = FeatureExtractor(pcap_path, limit=12000)
    features = []
    for feature_vector in feature_extractor.iter_features():
        if feature_vector is None:
            continue
        features.append(feature_vector)
        if len(features) >= 5000:  # Minimal learning window for a demo model
            break

    if not features:
        raise RuntimeError(
            "No features extracted. Ensure the PCAP is readable and dependencies are installed."
        )

    input_dim = len(features[0])
    kitnet = KitNET(input_dim=input_dim)

    # Unsupervised learning phase on normal traffic
    for row in features:
        kitnet.process(row)

    # Export to models directory
    models_dir = os.path.join(root, "models")
    os.makedirs(models_dir, exist_ok=True)
    out_path = os.path.join(models_dir, "kitsune_model.pkl")
    joblib.dump(kitnet, out_path)
    print(f"Saved Kitsune model to: {out_path}")


if __name__ == "__main__":
    main()


