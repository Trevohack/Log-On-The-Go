<div align="center"> 
  <img src="https://i.postimg.cc/1XwRVrWn/Screenshot-2025-12-31-193811.png" alt="" style="max-width:100%; border-radius:12px;"/> 
</div> 

<h1 align="center">Log On The Go</h1> 

<div align="center">
  <strong>Local-first security log analysis with on-demand intelligence.</strong><br>
  <b><i>Built for developers, sysadmins, and production servers</i></b> 
  <br><br> 
  <img alt="" src="https://img.shields.io/badge/status-active-ff4da6?style=for-the-badge">
  <img alt="" src="https://img.shields.io/badge/backend-fastapi-0a0a0a?style=for-the-badge&logo=python&logoColor=ff4da6">
  <img alt="" src="https://img.shields.io/badge/frontend-react-0a0a0a?style=for-the-badge&logo=react&logoColor=ff4da6">
  <img alt="" src="https://img.shields.io/badge/focus-security-ff4da6?style=for-the-badge"> 
  <img alt="" src="https://img.shields.io/static/v1?label=Tested&message=True&labelColor=000000&color=FFFFFF&style=for-the-badge&logo=checkmarx&logoColor=ff66cc">
</div> 

--- 

## 🚀 What is LOTG?

**Log On The Go (LOTG)** is a modern log analysis platform that lets you:
- Analyze security logs **on demand**
- Upload files or analyze logs by path
- Inspect risk levels, attack patterns, and timelines
- Keep everything **local-first** and controlled

No background magic.  
No forced cloud dependency.  
You decide when analysis happens.

---

## 🧩 Modes

### 🔹 Standard Mode (LOTG)
- Upload log files
- Analyze logs by file path
- View detailed security reports instantly

### 🔹 Server Mode (LOTG Serv)
- Designed for servers & businesses
- Secure access via credentials
- Analyze **pre-configured server log paths** 
- Same analysis engine, same results, cleaner workflow
- Make a user using `python -m app.init_users` 

> **LOTG Serv** runs locally but is structured for production environments.

---  

## 🔍 What Gets Analyzed?

LOTG supports a wide range of logs including:
- Linux auth logs (`auth.log`, `secure`)
- SSH authentication events
- Apache access logs
- Syslog-style files
- Mixed or unknown formats (graceful fallback)

Each analysis includes:
- Risk score & level (LOW / MEDIUM / HIGH)
- Suspicious IPs
- Brute-force attempts
- Attack chains & anomalies
- Timeline & narrative summary

---

## 🧠 How It Works

1. Choose a mode (Upload / Path / SERV)
2. Trigger analysis manually
3. Logs are parsed & normalized
4. Security patterns are detected
5. Results are returned as structured JSON
6. Frontend presents expandable, readable reports

Nothing is modified.  
Nothing runs in the background without you knowing.

---

## 🖥️ Tech Stack

**Backend**
- Python
- FastAPI
- Read-only log parsing

**Frontend**
- React (Vite)
- Modern, dark, security-focused UI
- Expandable analysis views

---

## ▶️ Running the App (Dev)

From the project root:

```bash
npm install concurrently --save-dev 
cd frontend && npm install 
npm run dev 
```


