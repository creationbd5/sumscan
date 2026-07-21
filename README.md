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
* **Url Scan Threat Intelligence:** Query live and historical threat intelligence records, IPs, and screenshots.
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
git clone [https://github.com/creationbd5/sumscan.git](https://github.com/creationbd5/sumscan.git) ~/sumscan && cd ~/sumscan && chmod +x install.sh && ./install.sh
