# PreTech-NIDS Project Structure

## 📁 Directory Organization

### 🚀 Core Application (`app/`)
- **`main.py`** - FastAPI main application entry point
- **`auth.py`** - User authentication and authorization system
- **`alert_system.py`** - Alert management and notification system
- **`pcap_analyzer.py`** - PCAP file analyzer
- **`geomap.py`** - Geographic mapping and attack location analysis
- **`report.py`** - Report generation and management
- **`timezone_utils.py`** - Timezone utility tools

### 🤖 Machine Learning (`models/`)
- **`trained_models/`** - Trained model files
  - `ae_model.h5` - Autoencoder model
  - `cnn_dnn_model.h5` - CNN-DNN model
  - `lstm_ae_model.h5` - LSTM autoencoder model
  - `rf_model.pkl` - Random Forest model
  - `kitsune_model.pkl` - Kitsune model
- **`model_assets/`** - Model-related resources
  - `scalers/` - Data standardization scalers
  - `thresholds/` - Model threshold files
  - `visualizations/` - Model visualization charts

### 📊 Data Management
- **`data/`** - Data file management
  - `pcap/` - PCAP network packet files
  - `exports/` - Exported data files
- **`dataset/`** - Training datasets
  - `CICIDS2017 Full dataset.csv` - Main training dataset
- **`samples/`** - Sample data
  - `BENIGN_samples.json` - Benign traffic samples
  - `ddos_samples.json` - DDoS attack samples
  - `portscan_samples.json` - Port scan samples

### 🛠️ Scripts (`scripts/`)
- **`database/`** - Database-related scripts
  - `export_database_schema_to_excel.py` - Database schema export
- **`data_processing/`** - Data processing scripts
  - `extract_BENIGN.py` - Extract benign traffic features
  - `extract_ddos_samples.py` - Extract DDoS samples
  - `extract_portscan_samples.py` - Extract port scan samples
  - `make_lstm_attack_input.py` - Generate LSTM training input
- **`training/`** - Model training scripts
  - `train_autoencoder.py` - Autoencoder training
  - `train_cnn_dnn.py` - CNN-DNN training
  - `train_lstm_ae.py` - LSTM autoencoder training
  - `train_rf.py` - Random Forest training
- **`admin/`** - Administration scripts
  - `create_admin.py` - Create administrator account
  - `manage_users.py` - User management
  - `setup_password_reset.py` - Password reset setup
  - `get_alert_id.py` - Get alert ID
- **`utilities/`** - Utility scripts
  - `csv_to_xlsx.py` - CSV to Excel conversion
  - `export_use_cases_csv.py` - Use cases export to CSV
  - `export_use_cases_xlsx_formatted.py` - Use cases export to Excel
  - `get_oauth_refresh_token.py` - OAuth token refresh

### 📚 Documentation (`docs/`)
- **`database_schema/`** - Database design documentation
  - `PreTech-NIDS_Database_Schema.docx` - Word format
  - `PreTech-NIDS_Database_Schema.xlsx` - Excel format
- **`use_cases/`** - Use case documentation
  - `UseCases.csv` - Use cases in CSV format
  - `UseCases_formatted.xlsx` - Use cases in Excel format
- **`diagrams/`** - System diagrams
  - `pretech-nids-activity/` - Activity diagrams
  - `pretech-nids-class/` - Class diagrams
  - `pretech-nids-sequence/` - Sequence diagrams
  - `pretech-nids-usecase/` - Use case diagrams

### 🧪 Testing (`tests/`)
- **`kitsune_test.py`** - Kitsune algorithm testing

### ⚙️ Configuration (`configs/`)
- **`config.py`** - Centralized configuration file

### 📦 Dependencies (`requirements/`)
- **`requirements.txt`** - Main dependencies
- **`requirements-dev.txt`** - Development dependencies

### 🌐 Frontend (`dashboard/`)
- Svelte.js frontend application
- Real-time monitoring interface
- User management interface

### 🔧 Other
- **`kitsune/`** - Kitsune anomaly detection algorithm implementation
- **`uploads/`** - User uploaded files
- **`venv/`** - Python virtual environment
- **`node_modules/`** - Node.js dependencies

## 🔄 File Movement Strategy

### ✅ **Safe to Move (Already Done)**
- Documentation files → `docs/`
- Test files → `tests/`
- Script files → `scripts/` (organized by functionality)

### ⚠️ **Requires Code Changes (Future)**
- Model files → `models/trained_models/`
- Data files → `data/` subdirectories
- Configuration file path updates

### 🚫 **Keep in Place (System Critical)**
- `app/` directory - Core application code
- `kitsune/` directory - Algorithm implementation
- Database connection configuration


