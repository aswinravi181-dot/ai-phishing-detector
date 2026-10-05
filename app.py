"""AI Phishing Detector - Flask backend (EDUCATIONAL PROTOTYPE)."""
import os
import sqlite3
from datetime import datetime

from flask import Flask, jsonify, render_template, request

from model import PhishingDetector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "history.db")

app = Flask(__name__)
detector = PhishingDetector()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT, input TEXT, label TEXT, risk TEXT, confidence REAL)"""
        )


@app.route("/")
def index():
    return render_template("index.html", train_size=detector.train_size)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    text = ((request.get_json(silent=True) or {}).get("text") or "").strip()
    if not text:
        return jsonify(error="Please enter a URL or message."), 400
    if len(text) > 2000:
        return jsonify(error="Input is too long (max 2000 characters)."), 400
    result = detector.analyze(text)
    with db() as conn:
        conn.execute(
            "INSERT INTO history (time, input, label, risk, confidence) VALUES (?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), text, result["label"], result["risk"], result["confidence"]),
        )
    return jsonify(result)


@app.route("/api/history")
def history():
    with db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM history ORDER BY id DESC LIMIT 50")]
        counts = {r["label"]: r["n"] for r in conn.execute("SELECT label, COUNT(*) n FROM history GROUP BY label")}
    return jsonify(items=rows, stats={
        "total": sum(counts.values()), "SAFE": counts.get("SAFE", 0),
        "SUSPICIOUS": counts.get("SUSPICIOUS", 0), "PHISHING": counts.get("PHISHING", 0)})


@app.route("/api/clear", methods=["POST"])
def clear():
    with db() as conn:
        conn.execute("DELETE FROM history")
    return jsonify(ok=True)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
