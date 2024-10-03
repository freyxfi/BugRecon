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

    
