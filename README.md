# SumScan - Web & Network Security Recon Suite

**SumScan** is a high-performance, multi-threaded security reconnaissance suite built with Python and CustomTkinter. Designed for penetration testers, security researchers, and system administrators, SumScan provides a sleek "Pure Black" aesthetic GUI for rapid network diagnostic, OSINT footprinting, and web application reconnaissance.

---

## 📸 Interface Preview

<p align="center">
  <img src="https://drive.google.com/uc?export=download&id=1qS7lkAPFsOXzbQkiI4OZhXJnDJ54P582" alt="SumScan GUI Preview" width="850"/>
</p>

---

## 🔥 Key Features

* **TCP Fast Connect Scanner:** High-speed multi-threaded port scanning with service banner identification.
* **Web Directory Enumeration:** Discover hidden files and endpoints using customized wordlists or standard SecLists paths.
* **Urlscan.io Threat Intelligence:** Query live and historical threat intelligence records, IPs, and screenshots.
* **OSINT & Subdomain Discovery:** Enumerate subdomains and detect linked social media footprints.
* **Web & Tech Stack Recon:** Identify underlying web servers, frameworks, and CMS setups.
* **DNS & WHOIS Query Engine:** Instant lookup for A, MX, NS, TXT records and WHOIS ownership details.
* **Shodan Public Host Lookup:** Retrieve open port summaries and public IP information via InternetDB.
* **Pure Dark Aesthetic GUI:** Centered responsive layout, dynamic pulse indicators, and GIF scanning animations.

---

## 🚀 Installation & Setup

### Option 1: Automated 1-Line Installer (Kali Linux)

Open your Kali Linux terminal and execute the following command to automatically download, install dependencies, create desktop shortcuts, and launch the tool:

```bash
git clone [https://github.com/creationbd5/SumScan.git](https://github.com/creationbd5/SumScan.git) ~/SumScan && cd ~/SumScan && chmod +x install.sh && ./install.sh

## Option 2: Manual Installation
Clone the Repository: Bash Command
git clone [https://github.com/creationbd5/SumScan.git](https://github.com/creationbd5/SumScan.git)
cd SumScan

## Install Required System & Python Dependencies:
sudo apt update
sudo apt install python3 python3-pip python3-tk -y
pip3 install customtkinter pillow dnspython --break-system-packages

## Run the Application:
python3 app.py

🛠️ Usage Guide
Enter your Target Host / URL (e.g., example.com or 192.168.1.1).

Select your desired Scan Mode from the dropdown menu.

Define port ranges or custom wordlist paths if applicable.

Click ▶ Start Scan to begin active reconnaissance.

Export your scan findings at any time using the 📥 Export Report button.

🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change or improve.

Feel free to submit feedback, bug reports, or feature requests.

📜 License
Distributed under the MIT License. See LICENSE for more information.
