CloudDrive — Multi‑Device Storage (Demo)
=======================================

A minimal full‑stack app that lets users register/login, add "devices" with capacities, upload files,
assign files to devices, and visualize storage usage across devices.

Tech
----
- Backend: FastAPI + SQLite + SQLAlchemy + JWT auth
- Frontend: Static HTML + Tailwind (CDN) + vanilla JS + Chart.js (CDN)
- File storage: Saved to `backend/storage/user_<id>/` on the server

Run locally
-----------
1) Create a virtualenv and install deps:

```
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2) Start the server:

```
uvicorn app:app --reload
```

3) Open http://127.0.0.1:8000 in your browser.

Notes
-----
- This demo keeps secrets in-code for simplicity. In production, set ENV vars and rotate keys.
- Storage used per device is computed from the sizes of files *assigned* to that device.
- "Disable" toggles online/offline. "Unbind" deletes the device and its assignments.
- For cloud production, use S3/GCS/Azure for object storage and serve the React/JS frontend via CDN.
