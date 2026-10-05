# AI Phishing Detector

> **Educational cybersecurity prototype.** Built for learning and demonstration only.
> It analyses text locally. It never opens, visits or attacks any URL or system, and it is not a replacement for professional security tools.

Enter a URL or a suspicious email/SMS and the app predicts **SAFE**, **SUSPICIOUS** or **PHISHING**, with risk level, confidence, reasons and a recommended action. No paid services or API keys are needed.

## How it works
1. `model.py` converts the input into 23 numeric features (URL length, hyphens, IP address, risky TLD, brand imitation, login keywords, urgent wording, requests for passwords/OTP, etc.).
2. A scikit-learn **Logistic Regression** model is trained at start-up on `data/dataset.csv` (about 100 labelled samples).
3. The model returns probabilities -> label + confidence. Risk = PHISHING probability + half of SUSPICIOUS probability (Low < 35%, Medium < 65%, High otherwise).
4. The same features generate the human-readable reasons.
5. Every scan is stored in a local SQLite file (`history.db`) and shown in the history table.

## Folder structure
```
ai-phishing-detector/
├── app.py              Flask backend + API routes
├── model.py            Feature extraction, ML model, reasons
├── requirements.txt
├── README.md
├── data/dataset.csv    Sample training data
├── templates/index.html
└── static/
    ├── style.css
    └── script.js
```

## Install and run (Windows + VS Code)
Open the folder in VS Code, then open a terminal (**Terminal > New Terminal**, PowerShell):
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
If activation is blocked, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
Open **http://127.0.0.1:5000** in your browser. Stop the server with `Ctrl + C`.

## Test inputs
| Input | Expected |
|---|---|
| `http://example-suspicious-site.com/login` | PHISHING / High |
| `http://paypal-secure-login.com/verify-account` | PHISHING / High |
| `http://192.168.1.5/admin/login` | PHISHING / High |
| `http://bit.ly/3xYzAb` | SUSPICIOUS / Medium |
| `https://www.google.com` | SAFE / Low |
| `URGENT: Your bank account is suspended. Verify your password and OTP at http://secure-bank-verify.top/login` | PHISHING / High |
| `Hi, are we still meeting for lunch tomorrow?` | SAFE / Low |

## API
- `POST /api/analyze` with `{"text": "..."}`
- `GET /api/history`
- `POST /api/clear`

## Limitations
Small training set and simple features, so mistakes are expected. Improve it by adding more rows to `data/dataset.csv` (`"text",LABEL`) and restarting the app.
