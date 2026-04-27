Mitigating Data Breach System

What is this project?
This is a desktop security application I built as my Capstone Project. It watches over your files in real-time and uses machine learning to catch suspicious behavior before it becomes a serious problem — things like ransomware, mass file deletions, or someone poking around where they shouldn't be.
The idea is simple: your data matters, and you deserve to know the moment something feels off.

What it can do

User Authentication
Accounts are protected with encrypted passwords and basic security policies — so only the right people get in.

Real-Time File Monitoring
Every file action — whether it's a creation, deletion, modification, or rename — gets tracked and logged as it happens. Nothing slips through unnoticed.

Remote Monitoring
The system can receive file activity from other devices over a network, so you're not just watching one machine. Remote logs show up right inside the app.

Machine Learning Detection
This is where it gets interesting. The app learns what "normal" looks like, and flags anything that doesn't fit — including ransomware behavior, floods of file activity, mass deletions, and unusual access patterns.

Threat Alerts
When something suspicious is detected, a popup alert fires immediately — showing you who, what, and where: the user, IP address, file activity, and what the model thinks is happening.

Logs & Reports
Everything gets stored. Activity logs are kept locally and can also be pushed to a MySQL database for longer-term record-keeping.

How it works

At its core, the system is always watching. File activity flows in continuously, gets analyzed by the ML model, and if something looks wrong — you'll know about it right away. It's designed to be as hands-off as possible while still keeping you in the loop when it counts.


Technologies Used

Python

Tkinter (GUI)

Machine Learning (River Library)

MySQL Database

Cryptography (Fernet, RSA, bcrypt)

Watchdog (File Monitoring)

Socket Programming (Network Monitoring)


Project Structure

├── file_explorer.py      # Main GUI app

├── file_monitor.py       # File monitoring + network listener

├── MLmodel.py            # ML detection logic

├── database_manager.py   # Database connection and queries

├── tools/                # Backup and utility scripts

├── log_data/             # Activity logs (not tracked in Git)

└── train/                # Training data (not tracked in Git)

How to Run

Install required libraries:

pip install -r requirements.txt

Run the application:

python file_explorer.py

A note on security

Some files are intentionally left out of this repository — encryption keys, logs, training data, and build files. These contain sensitive information and should never be committed to version control.

Why I built this

This project started as a Capstone requirement, but it turned into something I genuinely found interesting to work on. Combining real-time monitoring, machine learning, and cybersecurity concepts in one system pushed me to think about security not just as a feature, but as a foundation.
It's built for educational purposes, but the concepts behind it — anomaly detection, behavioral analysis, real-time alerting — are very much real-world problems worth solving.

