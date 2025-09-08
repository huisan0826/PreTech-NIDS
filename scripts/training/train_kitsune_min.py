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
    from FeatureExtractor import FE as FeatureExtractor  # type: ignore
    from KitNET.KitNET import KitNET  # type: ignore

    # Use CICIDS2017 PCAP files from E drive for training
    pcap_files = [
        "E:\\Monday-WorkingHours.pcap",
        "E:\\Tuesday-WorkingHours.pcap", 
        "E:\\Wednesday-workingHours.pcap",
        "E:\\Thursday-WorkingHours.pcap",
        "E:\\Friday-WorkingHours.pcap"
    ]
    
    # Check if any pcap files exist
    existing_files = [f for f in pcap_files if os.path.exists(f)]
    if not existing_files:
        raise FileNotFoundError(
            f"No CICIDS2017 PCAP files found. Expected files: {pcap_files}"
        )
    
    print(f"Found {len(existing_files)} CICIDS2017 PCAP files: {existing_files}")

    # Extract features from all available CICIDS2017 PCAP files
    # This will process multiple days of network traffic for comprehensive training
    features = []
    total_packets_processed = 0
    max_features_per_file = 20000  # Process more packets from each file for better training
    max_total_features = 100000    # Total limit across all files
    
    for pcap_file in existing_files:
        print(f"Processing {pcap_file}...")
        try:
            feature_extractor = FeatureExtractor(pcap_file, limit=max_features_per_file)
            file_features = []
            
            while len(file_features) < max_features_per_file:
                feature_vector = feature_extractor.get_next_vector()
                if feature_vector is None:
                    break
                file_features.append(feature_vector)
                total_packets_processed += 1
                
                # Stop if we've reached our total limit
                if len(features) + len(file_features) >= max_total_features:
                    break
                    
            features.extend(file_features)
            print(f"Extracted {len(file_features)} features from {os.path.basename(pcap_file)}")
            
            # Stop if we've reached our total limit
            if len(features) >= max_total_features:
                break
                
        except Exception as e:
            print(f"Warning: Failed to process {pcap_file}: {e}")
            continue

    if not features:
        raise RuntimeError(
            "No features extracted from CICIDS2017 PCAP files. Ensure the files are readable and dependencies are installed."
        )
    
    print(f"✅ Successfully extracted {len(features)} features from {total_packets_processed} packets across {len(existing_files)} files")

    input_dim = len(features[0])
    print(f"🔧 Initializing KitNET with input dimension: {input_dim}")
    kitnet = KitNET(n=input_dim)

    # Unsupervised learning phase on CICIDS2017 traffic
    print("🚀 Starting unsupervised training on CICIDS2017 data...")
    for i, row in enumerate(features):
        if i % 10000 == 0 and i > 0:
            print(f"Processed {i}/{len(features)} features...")
        kitnet.process(row)
    
    print(f"✅ Training completed on {len(features)} feature vectors")

    # Export to models directory
    models_dir = os.path.join(root, "models")
    os.makedirs(models_dir, exist_ok=True)
    out_path = os.path.join(models_dir, "kitsune_model.pkl")
    joblib.dump(kitnet, out_path)
    print(f"💾 Saved Kitsune model trained on CICIDS2017 data to: {out_path}")
    print(f"📊 Model trained on {len(features)} features from {len(existing_files)} CICIDS2017 PCAP files")


if __name__ == "__main__":
    main()


