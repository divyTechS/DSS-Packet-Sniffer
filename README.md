
---

```markdown
# 🛰️ DSS Packet Sniffer

A modern, GUI-based **network packet sniffer** built with **Python and PyQt5**, designed to analyze live network traffic in real-time — with **aesthetic dark theme, sapphire accents, ML-ready architecture**, and a smooth user experience.

---

## 🚀 Features

- 🔍 **Real-Time Packet Capture** – View live packets flowing through your system.  
- 🧠 **Smart Classification (ML-Ready)** – Architecture designed to integrate machine learning for detecting suspicious packets.  
- 🌈 **Modern Dark Sapphire UI** – Beautiful, minimal, and futuristic interface built with PyQt5.  
- 📊 **Traffic Statistics Dashboard** – Shows live packet counts, traffic graph, and color-coded alerts.  
- 💾 **Logging & Export** – Save captured packets and export logs for later analysis.  
- ⚙️ **Root-Aware Execution** – Captures packets using `scapy` with root permissions on Linux.  
- 🧰 **Cross-Platform Ready** – Tested on Linux and Windows; runs standalone via executable file.  

---

## 🧩 Folder Structure

```

DSS-Packet-Sniffer/
├── src/
│   └── main.py              # Main application file
├── assets/
│   ├── logo.png             # App logo
│   └── Orbitron.ttf         # Custom font
├── dist/
│   └── Safffire/
│       └── Safffire         # Built executable (Linux)
├── requirements.txt
├── README.md
└── LICENSE (optional)

````

---

## 🛠️ Installation

### **Option 1: Run from Source**
```bash
git clone https://github.com/divyTechS/DSS-Packet-Sniffer.git
cd DSS-Packet-Sniffer/src
pip install -r ../requirements.txt
sudo python3 main.py
````

> ⚠️ Root access (`sudo`) is required for live packet capture.

---

### **Option 2: Run the Executable (Recommended)**

```bash
cd dist/Safffire
sudo ./Safffire
```

✅ No need to install dependencies.
✅ GUI launches instantly.

---

## 🔐 Root Permission Note

Network sniffing requires access to raw sockets, which are privileged operations.
Run the app with **root/admin rights** to enable full packet capture.

On Linux:

```bash
sudo ./Safffire
```

On Windows (future builds):

> Right-click → Run as Administrator

---

## 📸 Preview (Optional)

*(You can add screenshots later here)*

---

## 💡 Tech Stack

* **Language:** Python 3
* **GUI Framework:** PyQt5
* **Packet Capture:** Scapy
* **Machine Learning (Optional):** Scikit-learn, TensorFlow-ready
* **Builder:** PyInstaller

---

## 🧠 Future Enhancements

* Integration of trained ML models for anomaly detection
* Packet filtering and protocol statistics
* Multi-interface support
* Cross-platform (.exe and .AppImage) releases

---

## 👨‍💻 Author

**Divyesh Shivdas Swarge**
🎓 B.Tech CSE | IIITDM Jabalpur
🌐 [Portfolio](https://divytechs.vercel.app/)
💼 [LinkedIn](https://in.linkedin.com/in/divyesh-shivdas-swarge-638128324)
📧 [divyeshtechs@gmail.com](mailto:divyeshtechs@gmail.com)

---

## 🪪 License

This project is open-source under the **MIT License**.
Feel free to modify and distribute with attribution.

---

### ⭐ If you like this project, please consider giving it a star on GitHub!

```

---

