"""
PreTech-NIDS Configuration File
Centralized configuration for paths, database settings, and system parameters
"""

import os
from pathlib import Path

# Base project directory
BASE_DIR = Path(__file__).parent.parent

# Database Configuration
MONGODB_URI = "mongodb://localhost:27017"
DATABASE_NAME = "PreTectNIDS"

# Model Paths
MODELS_DIR = BASE_DIR / "models"
TRAINED_MODELS_DIR = MODELS_DIR / "trained_models"
MODEL_ASSETS_DIR = MODELS_DIR / "model_assets"
SCALERS_DIR = MODEL_ASSETS_DIR / "scalers"
THRESHOLDS_DIR = MODEL_ASSETS_DIR / "thresholds"
VISUALIZATIONS_DIR = MODEL_ASSETS_DIR / "visualizations"

# Data Paths
DATA_DIR = BASE_DIR / "data"
DATASET_DIR = BASE_DIR / "dataset"
SAMPLES_DIR = BASE_DIR / "samples"
PCAP_DIR = DATA_DIR / "pcap"
EXPORTS_DIR = DATA_DIR / "exports"

# Upload Paths
UPLOADS_DIR = BASE_DIR / "uploads"
AVATARS_DIR = UPLOADS_DIR / "avatars"

# Scripts Paths
SCRIPTS_DIR = BASE_DIR / "scripts"
DATABASE_SCRIPTS_DIR = SCRIPTS_DIR / "database"
DATA_PROCESSING_SCRIPTS_DIR = SCRIPTS_DIR / "data_processing"
TRAINING_SCRIPTS_DIR = SCRIPTS_DIR / "training"
ADMIN_SCRIPTS_DIR = SCRIPTS_DIR / "admin"
UTILITIES_SCRIPTS_DIR = SCRIPTS_DIR / "utilities"

# Documentation Paths
DOCS_DIR = BASE_DIR / "docs"
DATABASE_SCHEMA_DIR = DOCS_DIR / "database_schema"
USE_CASES_DIR = DOCS_DIR / "use_cases"
DIAGRAMS_DIR = DOCS_DIR / "diagrams"

# Test Paths
TESTS_DIR = BASE_DIR / "tests"

# Requirements Paths
REQUIREMENTS_DIR = BASE_DIR / "requirements"

# Ensure directories exist
def ensure_directories():
    """Create necessary directories if they don't exist"""
    directories = [
        MODELS_DIR, TRAINED_MODELS_DIR, MODEL_ASSETS_DIR, SCALERS_DIR, 
        THRESHOLDS_DIR, VISUALIZATIONS_DIR, DATA_DIR, DATASET_DIR, 
        SAMPLES_DIR, PCAP_DIR, EXPORTS_DIR, UPLOADS_DIR, AVATARS_DIR,
        SCRIPTS_DIR, DATABASE_SCRIPTS_DIR, DATA_PROCESSING_SCRIPTS_DIR,
        TRAINING_SCRIPTS_DIR, ADMIN_SCRIPTS_DIR, UTILITIES_SCRIPTS_DIR,
        DOCS_DIR, DATABASE_SCHEMA_DIR, USE_CASES_DIR, DIAGRAMS_DIR,
        TESTS_DIR, REQUIREMENTS_DIR
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

# Model file paths
def get_model_paths():
    """Get all model-related file paths"""
    return {
        "ae_model": TRAINED_MODELS_DIR / "ae_model.h5",
        "ae_scaler": SCALERS_DIR / "ae_scaler.pkl",
        "ae_threshold": THRESHOLDS_DIR / "ae_threshold.txt",
        "ae_visualization": VISUALIZATIONS_DIR / "ae_mse_threshold.png",
        
        "lstm_ae_model": TRAINED_MODELS_DIR / "lstm_ae_model.h5",
        "lstm_ae_scaler": SCALERS_DIR / "lstm_ae_scaler.pkl",
        "lstm_ae_threshold": THRESHOLDS_DIR / "lstm_ae_threshold.txt",
        "lstm_ae_visualization": VISUALIZATIONS_DIR / "lstm_ae_mse.png",
        
        "cnn_dnn_model": TRAINED_MODELS_DIR / "cnn_dnn_model.h5",
        "cnn_dnn_scaler": SCALERS_DIR / "cnn_dnn_scaler.pkl",
        
        "rf_model": TRAINED_MODELS_DIR / "rf_model.pkl",
        "rf_scaler": SCALERS_DIR / "rf_scaler.pkl",
        "rf_visualization": VISUALIZATIONS_DIR / "rf_feature_importance.png",
        
        "kitsune_model": TRAINED_MODELS_DIR / "kitsune_model.pkl"
    }

# Dataset paths
def get_dataset_paths():
    """Get all dataset-related file paths"""
    return {
        "cicids2017": DATASET_DIR / "CICIDS2017 Full dataset.csv",
        "benign_samples": SAMPLES_DIR / "BENIGN_samples.json",
        "ddos_samples": SAMPLES_DIR / "ddos_samples.json",
        "portscan_samples": SAMPLES_DIR / "portscan_samples.json"
    }

if __name__ == "__main__":
    ensure_directories()
    print("✅ All directories created successfully!")
