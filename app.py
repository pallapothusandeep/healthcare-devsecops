import hmac
import os

from flask import Flask, jsonify, request

app = Flask(__name__)
API_KEY = os.environ.get("API_KEY", "")

# Demo data only - fictional patients with masked personal details
PATIENTS = [
    {"id": "P1001", "name": "R*** Kumar", "age": 45, "ward": "Cardiology", "phone": "******4321"},
    {"id": "P1002", "name": "S*** Reddy", "age": 32, "ward": "Orthopedics", "phone": "******8812"},
    {"id": "P1003", "name": "A*** Sharma", "age": 58, "ward": "General Medicine", "phone": "******1290"},
]

HOME = """
<html><body style="font-family:Arial;background:#0f766e;color:white;text-align:center;padding-top:60px">
<h1>PBL-III Task 9: DevSecOps in a Healthcare System</h1>
<h2>Secure Patient Portal</h2>
<p>Secret Scan | SAST | Dependency Scan | IaC Scan | Image Scan | Secure Kubernetes Deployment</p>
<p>Patient API (/api/patients) is protected - access requires a valid API key.</p>
</body></html>
"""


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def home():
    return HOME


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/patients")
def patients():
    key = request.headers.get("X-API-Key", "")
    if not API_KEY or not hmac.compare_digest(key.encode(), API_KEY.encode()):
        return jsonify(error="Unauthorized - valid API key required"), 401
    return jsonify(patients=PATIENTS)
