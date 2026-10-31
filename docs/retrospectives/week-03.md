# Retrospective: Week 3

**Date:** 16 February 2026

## Accomplished

- **Security vertical slice:** moved the hard-coded API key out of `app.py` into a `.env` file excluded from Git.
- **Database persistence:** finalised SQLite integration for saving and retrieving secrets.
- **Authentication:** implemented `X-API-Key` header validation on secured routes.

## Challenges and fixes

| Issue | Fix |
| :--- | :--- |
| Unresolved imports for `os` and `load_dotenv` | Corrected imports and installed `python-dotenv` |
| Indentation error on a global variable | Moved `VALID_API_KEY` to module level |

## Key learning

Environment variables are the standard way to keep secrets out of source control while letting the same code run in different environments.
