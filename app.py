from flask import Flask, request, jsonify
from flask_cors import CORS
from collector import SystemInventory
import logging
import os
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

# Create reports directory if not exists
os.makedirs("reports", exist_ok=True)

inventory = SystemInventory()

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }), 200

@app.route('/api/agent/report', methods=['POST'])
def receive_agent_report():
    try:
        data = request.json
        agent_id = data.get("agent_id", "unknown")
        if not agent_id:
            return jsonify({"error": "Missing agent_id"}), 400

        with open(f"reports/{agent_id}.json", "w") as f:
            json.dump(data, f, indent=2)

        return jsonify({"status": "received", "agent_id": agent_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/<agent_id>', methods=['GET'])
def get_agent_report(agent_id):
    try:
        report_path = f"reports/{agent_id}.json"
        if not os.path.exists(report_path):
            return jsonify({"error": "Report not found"}), 404

        with open(report_path, "r") as f:
            data = json.load(f)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/system-info', methods=['GET'])
def get_system_info():
    try:
        info = inventory.get_system_info()
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports', methods=['GET'])
def get_all_reports():
    try:
        reports = []
        for filename in os.listdir("reports"):
            if filename.endswith(".json"):
                with open(os.path.join("reports", filename), "r") as f:
                    data = json.load(f)
                    reports.append(data)
        return jsonify(reports), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ Ensure Gunicorn can find the app object
# If running via gunicorn, this line is used
application = app

# If running directly via `python app.py`, this will still work
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
