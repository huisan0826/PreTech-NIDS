# PreTech-NIDS: Deep Learning-Based Network Intrusion Detection System

## Project Overview

PreTech-NIDS is a deep learning-based network intrusion detection system that uses advanced algorithms such as Autoencoder and KitNET to detect anomalous network traffic and potential attacks.

## Key Features

- 🚀 **Deep Learning Detection**: Uses autoencoder for anomaly detection
- 🔍 **Multiple Algorithm Support**: Integrates KitNET and traditional machine learning algorithms
- 📊 **Real-time Monitoring**: Real-time network traffic analysis and alerting
- 🌐 **Web Interface**: Modern Svelte.js dashboard
- 📈 **Visualization Analysis**: Detailed attack statistics and geographic distribution maps
- 🔐 **User Authentication**: Complete user management and access control

## Technical Architecture

### Backend
- **Python**: Core detection algorithms
- **FastAPI**: RESTful API service
- **MongoDB**: Data storage
- **TensorFlow/Keras**: Deep learning models

### Frontend
- **Svelte.js**: Modern frontend framework
- **Chart.js**: Data visualization
- **Tailwind CSS**: Styling framework

### Machine Learning
- **Autoencoder**: Core anomaly detection algorithm
- **KitNET**: Efficient unsupervised learning
- **Feature Engineering**: Network traffic feature extraction

## Project Structure

```
PreTech-NIDS/
├── A-NIDS/              # Autoencoder NIDS implementation
├── app/                 # FastAPI backend application
├── dashboard/           # Svelte.js frontend dashboard
├── kitsune/            # KitNET algorithm implementation
├── models/             # Trained model files
├── data/               # Datasets and samples
├── samples/            # Attack sample features
└── scripts/            # Utility scripts
```

## Quick Start

### Requirements
- Python 3.8+
- Node.js 16+
- MongoDB

### Installation Steps

1. **Clone Repository**
```bash
git clone https://github.com/huisan0826/PreTech-NIDS.git
cd PreTech-NIDS
```

2. **Install Python Dependencies**
```bash
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

3. **Install Frontend Dependencies**
```bash
cd dashboard
npm install
```

4. **Start Services**
```bash
# Start backend
python -m uvicorn app.main:app --reload

# Start frontend (new terminal)
cd dashboard
npm run dev
```

## Usage

1. Visit `http://localhost:5173` to open the dashboard
2. Upload network traffic packet files (.pcap files)
3. System will automatically analyze and detect anomalies
4. View real-time alerts and statistics

## Dataset

The project uses the CICIDS2017 dataset for model training, which includes various types of network attacks:
- DDoS attacks
- Port scanning
- Brute force attacks
- Malware propagation

## Contributing

We welcome Issue submissions and Pull Requests to improve the project!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or suggestions, please contact us through:
- Submit GitHub Issues
- Send email to: [your-email@example.com]

## Acknowledgments

Thanks to all researchers and developers who have contributed to the fields of cybersecurity and machine learning.
