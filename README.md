# Overview

BugRecon is an automated bug hunting tool designed to streamline the reconnaissance phase of bug bounty hunting and penetration testing. It performs essential tasks such as subdomain enumeration, port scanning, directory brute-forcing, vulnerability scanning, and screenshot capturing. By automating these tasks, BugRecon allows security researchers to focus on deeper analysis and exploitation, enhancing efficiency and effectiveness in identifying vulnerabilities.

# Features

1. Target Input: Prompts the user to enter the target domain.
2. Reconnaissance Depth: Allows selection of recon depth (shallow, medium, deep) to customize the extent of scanning.
3. Subdomain Enumeration: Retrieves subdomains using crt.sh.
4. Port Scanning: Identifies open ports using nmap.
5. Directory Brute-Forcing: Discovers hidden directories using ffuf.
6. Vulnerability Scanning: Checks for common vulnerabilities like SQL Injection (SQLi) and Cross-Site Scripting (XSS).
7. Screenshot Capturing: Takes screenshots of discovered web applications using EyeWitness.
8. Report Generation: Compiles findings into a comprehensive report.
9. Modular Design: Although provided as a single script, the tool is structured for easy expansion and integration of additional features.

    
# Prerequisites
Before using BugRecon, ensure that the following tools and dependencies are installed on your system:

## External Tools
1. Python 3.6+
   
    [Download Python](https://www.python.org/downloads/)
2. Nmap Install

   `go install github.com/ffuf/ffuf@latest`
3. ffuf (Fuzz Faster U Fool)

   `go install github.com/ffuf/ffuf@latest`

4. EyeWitness

    ```
      git clone https://github.com/FortyNorthSecurity/EyeWitness.git
      cd EyeWitness/Python/setup
      python setup.py install
    ```

# Python Packages

Install the required Python packages using pip

`pip install -r requirements.txt
`
