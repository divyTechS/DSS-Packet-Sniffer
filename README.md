🧾 README.md
# 🧠 DSS Packet Sniffer

**DSS Packet Sniffer** is a modern, intelligent network analysis tool built with **PyQt5** and **Scapy**.  
It features a clean sapphire-themed GUI, real-time packet capture, machine-learning based anomaly detection,  
and an interactive packet-inspection popup — all wrapped into a beautiful standalone Linux app.

---

## 🚀 Features

- 🌐 Real-time packet capture (supports TCP, UDP, ICMP, etc.)
- 🤖 ML-based anomaly detection for suspicious traffic
- 🧩 Interactive packet detail viewer (enter packet serial number to inspect)
- 🌓 Sleek dark-themed PyQt5 UI with sapphire-blue accents
- 💾 Packet logging and session management
- ⚡ Lightweight executable — no dependencies needed once built

---

## 🛠️ Tech Stack

| Component | Technology |
|------------|-------------|
| Frontend GUI | PyQt5 |
| Packet Sniffing | Scapy |
| ML Model | Scikit-Learn (integrated anomaly detection) |
| Theme / Fonts | Custom dark theme + Orbitron font |

---

## 🧰 Installation (Linux)

1. **Download the executable**
   ```bash
   git clone https://github.com/<yourusername>/DSS-Packet-Sniffer.git
   cd DSS-Packet-Sniffer/dist


Make it executable

chmod +x ./Safffire


Grant packet capture permissions (one-time setup)

sudo setcap cap_net_raw,cap_net_admin=eip ./Safffire


Run normally

./Safffire

🧩 Run from Source (for developers)
git clone https://github.com/<yourusername>/DSS-Packet-Sniffer.git
cd DSS-Packet-Sniffer/src
pip install -r ../requirements.txt
sudo python3 main.py

📂 Folder Structure
DSS-Packet-Sniffer/
├── assets/
│   ├── logo.png
│   └── Orbitron.ttf
├── src/
│   └── main.py
├── dist/
│   └── Safffire
├── README.md
├── LICENSE
└── requirements.txt

🧑‍💻 Author

Divyesh Shivdas Swarge
B.Tech CSE @ IIITDM Jabalpur
🔗 LinkedIn
https://in.linkedin.com/in/divyesh-shivdas-swarge-638128324
🌐 Portfolio
https://divytechs.vercel.app/