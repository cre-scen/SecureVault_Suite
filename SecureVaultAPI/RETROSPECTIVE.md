# Weekly Retrospective: Week 3
**Date:** February 16, 2026

## 🎯 What I Accomplished
* **Security Vertical Slice:** Successfully moved the hardcoded API key out of `app.py` and into a protected `.env` file.
* **Database Persistence:** Finalized SQLite integration to save and retrieve data strings.
* **Authentication:** Implemented `X-API-Key` header validation for all secure routes.

## 🛠️ Challenges & Solutions
* **Issue:** Red squiggles under `os` and `load_dotenv`. 
* **Fix:** Corrected imports and ran `pip install python-dotenv`.
* **Issue:** Indentation error on the global variable.
* **Fix:** Aligned `VALID_API_KEY` to the far-left margin.

## 💡 Key Learning
I learned that environment variables are the standard way to keep secrets off GitHub while still allowing the app to run securely in different environments.