# PreTech-NIDS

A practical Network Intrusion Detection System (NIDS) featuring multi-model inference (Kitsune, Autoencoder, LSTM, CNN+DNN, Random Forest), real-time packet capture detection, PCAP offline analysis, alerting, geospatial visualization, and a Svelte-based dashboard.

## Highlights
- FastAPI backend + Svelte SPA frontend
- Real-time detection on selected network interfaces
- PCAP upload & offline multi-model analysis
- Alerting with severity and filters + in-app notifications
- Attack Map with recent attacks and country statistics
- Reports with pagination, rich filters, export to CSV/JSON
- Role-based access control (Viewer, Security Analyst, Administrator)

## Directory Structure (key parts)
- `app/`: FastAPI services (auth, alerts, geomap, pcap analyzer, reports, main app)
- `dashboard/`: Svelte single-page frontend (routes, components)
- `models/`: Trained models, scalers, thresholds, visualizations
- `scripts/`: Training, evaluation, data processing, admin utilities
- `dataset/`: CICIDS2017 CSV (example)

## Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- MongoDB 5+ (local or Atlas)
- Windows, macOS, or Linux

## Quick Start

### 1) Clone & prepare
```bash
# Clone
git clone <your-repo-url>.git
cd PreTech-NIDS

# (Optional) Create virtual env
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# Install Python deps
pip install -r requirements/requirements.txt
```

### 2) Configure environment
Create a `.env` file in the project root (same level as `app/`):
```bash
# MongoDB (prefer Atlas in production)
MONGODB_URI=mongodb://localhost:27017

# JWT & security
SECRET_KEY=change-this-to-a-long-random-string
ACCESS_TOKEN_EXPIRE_MINUTES=120

# CORS (frontend dev URLs)
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# SMTP for email (OTP / password reset / registration verify)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASS=your_smtp_app_password
SMTP_SENDER_NAME=PreTech-NIDS
SMTP_USE_TLS=true
```

### 3) Start backend
```bash
# From repo root
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Backend will be available at `http://localhost:8000`.
- Static uploads served at `/static`
- Routers registered under: `/auth`, `/api/geomap`, `/api/pcap`, `/api/alerts` and reports endpoints at `/report*`

### 4) Start frontend (dashboard)
```bash
cd dashboard
npm ci
npm run dev
```
Dashboard will run at `http://localhost:5173` by default.

## User Roles & Functionalities

### Viewers
- Sign up (register) with email verification (OTP)
- Sign in (log in) with JWT-based session
- Edit profile (including avatar upload/delete)
- Change password
- Reset forgotten password via email OTP
- View Detection Reports with pagination and filters
- View the Attack Map of recent attacks
- Receive basic alert notifications

### Security Analysts
- Run Manual Testing by submitting feature vectors for inference
- Start/stop Real-time Detection on available network interfaces
- Run PCAP Analysis and view multi-model results
- Review Detection Reports with advanced filters (model/status/type/interface/date)
- Export reports to CSV/JSON (with permission)
- View and triage Alerts (severity, time, resolution status)

### Administrators
- Manage users and roles/permissions
- Delete specific detection reports (with permission)
- Adjust alerting policies/thresholds (via provided settings/scripts)
- Oversee configurations relevant to user workflows

## Typical Workflows
- Manual Testing: Navigate to `Manual Testing`, paste feature vector(s), select model, run inference, review report & alerts.
- Real-time Detection: Go to `Real-time Detection`, select network interface, choose a model or multi-model, start capture.
- PCAP Analysis: Open `PCAP Analyzer`, upload `.pcap`, review aggregated multi-model findings and threat analysis.
- Reports & Export: Use `Reports`, filter by model/status/type/interface/date, export (CSV/JSON) if permitted.
- Alerts: Open `Alerts` to review recent alerts, filter, and triage.
- Attack Map: Use `Attack Map` to visualize recent attack locations and country statistics.

## Datasets, Models, and Scripts
- Dataset: Example `dataset/CICIDS2017 Full dataset.csv`
- Models: Pretrained artifacts under `models/` (e.g., `kitsune_model.pkl`, `*_model.h5`, scalers, thresholds)
- Training: `scripts/training/` (RF, Autoencoder, LSTM, CNN+DNN, Kitsune)
- Evaluation: `scripts/evaluation/evaluate_all.py`
- Data prep: `scripts/data_processing/` (sample extraction, LSTM input builder)
- Admin utilities: `scripts/admin/` (create admin, manage users, setup password reset)

Example: run RF training quickly
```bash
python scripts/training/train_rf.py
```

## Important Endpoints (overview)
- Auth: `/auth/register/*`, `/auth/login`, `/auth/password`, `/auth/avatar`
- Reports: `/report`, `/reports`, `/reports/stats`, `/reports/export`, `DELETE /reports/{id}`
- PCAP: `/api/pcap/upload`
- Realtime & Predict: `/predict`, `/interfaces` (listing)
- Attack Map: `/api/geomap/recent-attacks`, `/api/geomap/statistics`
- Alerts: `/api/alerts/*` (recent, pagination, filters)

## Troubleshooting
- MongoDB connection failed
  - Ensure `MONGODB_URI` is correct and MongoDB is running (or Atlas reachable)
- Email sending errors (SMTP 535/534/etc.)
  - Verify SMTP credentials, TLS/port; consider app passwords for Gmail/Outlook
- CORS errors in browser
  - Update `CORS_ORIGINS` to include your frontend origin
- Models not found / inference errors
  - Ensure files exist under `models/` and versions match the code; re-run training scripts if needed
- Permission denied on feature pages
  - Confirm your user role and assigned permissions; login again if role changed

## Security Notes
- Use strong, unique `SECRET_KEY` in production
- Serve over HTTPS; set secure cookies and proper CORS settings
- Lock down SMTP credentials and database access

## Acknowledgments
- CICIDS2017 dataset
- Kitsune research and implementations
