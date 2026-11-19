# IntelliGuard – Website Safety & Phishing Link Checker

IntelliGuard is a modern, easy-to-use website security tool. It allows anyone—even with no background in computers or cybersecurity—to paste any link received in an email, message, or social media post and find out within seconds whether it is safe to open or a potential scam.

---

## ✨ Features

- **⚡ Instant 3-Second Verdict**: Large, clear visual card showing whether the link is **Safe to Visit**, **Low Risk**, **Suspicious**, or **Dangerous**.
- **🚦 Easy Safety Meter**: An intuitive color-coded meter showing the website's risk level at a glance.
- **💡 Plain English Advice ("What to do")**: Tells you straightforwardly whether it is safe to click, or if you should close and delete the message.
- **📋 Simple Reasons Checklist**: Explains why a link received its rating in everyday terms (e.g., "Verified official website", "Fake PayPal imitation", "Shortened link hiding destination").
- **📁 Check Multiple Links at Once**: Paste several links or upload a spreadsheet to check all of them in bulk.
- **🕒 Saved Scans**: Simple record of previously checked links on your device.

---

## 🚦 How the Ratings Work

| Status | Color | What it means | What you should do |
| :--- | :---: | :--- | :--- |
| **Safe to Visit** | 🟢 Green | Verified genuine website with secure connection | Safe to visit and browse |
| **Low Risk** | 🔵 Blue | Normal website with no scam signals | Safe for standard browsing |
| **Suspicious** | 🟠 Orange | Link shortener or unusual pattern hiding destination | Check sender; avoid typing passwords |
| **Dangerous** | 🔴 Red | High risk of scam, fake brand imitation, or password trap | **Do not click; delete message immediately** |

---

## 🚀 How to Run IntelliGuard

### 1. Open Terminal in the Project Folder
```powershell
cd "c:\Users\windows 11\Desktop\tis\IntelliGuard_URL_Detection_Project\IntelliGuard_URL_Detection"
```

### 2. Activate the Environment
```powershell
..\venv\Scripts\Activate.ps1
```

### 3. Start the Application
```bash
streamlit run app.py
```

Your browser will open automatically at `http://localhost:8501`.
