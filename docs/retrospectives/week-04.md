# Retrospective: Week 4

**Milestone:** SecureVault API and LogSentinel integration

## Accomplished

- **Live logging:** configured Flask logging to stream request events to `app.log`.
- **File-tailing monitor:** built a Python monitor that follows the API's log without locking the file.
- **Stateful detection:** implemented threshold-based detection (5 failures in 60 seconds).
- **Alerting:** added a real-time terminal alert for brute-force detection.

## Design: temporal window

Instead of alerting on every failed login, the monitor tracks failure timestamps and only alerts when enough failures fall inside the window. This separates a person who forgot a password from an automated attack.

## Lessons learned

- **Relative paths:** paths like `../` depend on the current working directory. Resolving them from the script's own location is more reliable. This was fixed later.
- **File I/O:** seeking to the end of the file on start-up stops historical entries from triggering alerts after a restart.
- **Environments:** the virtual environment must be activated in every new terminal.
