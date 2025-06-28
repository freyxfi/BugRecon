# BugRecon 

**BugRecon** is an automated bug-hunting tool designed to streamline the reconnaissance phase of bug bounty hunting and penetration testing. It automates essential tasks like subdomain enumeration, port scanning, directory brute-forcing, vulnerability scanning, and screenshot capturing. This allows security researchers to focus on deeper analysis and exploitation, increasing both efficiency and effectiveness in identifying vulnerabilities.

---

## 🚀 Features

1. **Target Input**: Prompts the user to enter the target domain.
2. **Reconnaissance Depth**: Allows you to choose between shallow, medium, or deep scanning levels.
3. **Subdomain Enumeration**: Retrieves subdomains using crt.sh.
4. **Port Scanning**: Identifies open ports with `nmap`.
5. **Directory Brute-Forcing**: Discovers hidden directories using `ffuf`.
6. **Vulnerability Scanning**: Detects common vulnerabilities like SQL Injection (SQLi) and Cross-Site Scripting (XSS).
7. **Screenshot Capturing**: Captures screenshots of discovered web applications using `EyeWitness`.
8. **Report Generation**: Compiles all findings into a comprehensive, easy-to-read report.
9. **Modular Design**: Structured for easy expansion, allowing for the integration of additional features as needed.

---

## 📋 Prerequisites

Ensure that the following dependencies are installed on your system before using BugRecon:

### External Tools

1. **Python 3.6+**
    - [Download Python](https://www.python.org/downloads/)

2. **Nmap**
    - Installation:
      ```bash
      sudo apt-get install nmap
      ```

3. **ffuf (Fuzz Faster U Fool)**
    - Installation:
      ```bash
      go install github.com/ffuf/ffuf@latest
      ```

4. **EyeWitness**
    - Installation:
      ```bash
      git clone https://github.com/FortyNorthSecurity/EyeWitness.git
      cd EyeWitness/Python/setup
      python setup.py install
      ```

### Python Packages

Install the required Python packages by running:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Installation

1. **Clone the Repository**  
   Clone the BugRecon repository to your local machine:
   ```bash
   git clone https://github.com/freyxfi/BugRecon
   cd BugRecon
   ```

2. **Install Python Dependencies**  
   Use `pip` to install all necessary Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. **Ensure External Tools are Installed**  
   Make sure that `nmap`, `ffuf`, and `EyeWitness` are installed and added to your system's PATH.

---

## 🚀 Usage

To run BugRecon, execute the following:

```bash
python bug_recon.py
```

You will be prompted to enter the target domain and select the reconnaissance depth (shallow, medium, deep).

---

## 📊 Recon Depth Levels (Coming Soon)

Detailed explanation on what each recon depth level (shallow, medium, deep) covers and how it customizes your scans.

---

## 📝 Example (Coming Soon)

An example of BugRecon in action:

```bash
BugRecon Report for example.com

Subdomains Found:
- subdomain1.example.com
- subdomain2.example.com

Open Ports:
- 80
- 443

Vulnerabilities:
- subdomain1.example.com (Port 80)
  - Possible SQL Injection
  - Possible XSS
```

---

## 🧾 Generated Report (example.com_report.txt)

A detailed report will be generated after the scan in the following format:

```
Bug Recon Report for example.com

Subdomains Found:
- subdomain1.example.com
- subdomain2.example.com

Open Ports:
- 80
- 443
- 8080

Vulnerabilities:
- subdomain1.example.com (Port 80)
  - Possible SQL Injection
  - Possible XSS
- subdomain3.example.com (Port 443)
  - Possible XSS
```

---

## 🛠️ Contributing (Coming Soon)

Contributions are welcome! Feel free to submit pull requests to enhance BugRecon. Follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Push to the branch (`git push origin feature-branch`).
5. Submit a pull request.

---

## 📄 License

This project is licensed under the MIT License.

---

## 🎉 Contributors

Special thanks to all the contributors who have helped improve BugRecon!

<!-- Add contributor avatars automatically with this placeholder -->
<a href="https://github.com/freyxfi/BugRecon/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=freyxfi/BugRecon" />
</a>

---
