# Overview

BugRecon is an automated bug hunting tool designed to streamline the reconnaissance phase of bug bounty hunting and penetration testing. It performs essential tasks such as subdomain enumeration, port scanning, directory brute-forcing, vulnerability scanning, and screenshot capturing. By automating these tasks, BugRecon allows security researchers to focus on deeper analysis and exploitation, enhancing efficiency and effectiveness in identifying vulnerabilities.

# Features

    Target Input: Prompts the user to enter the target domain.
    Reconnaissance Depth: Allows selection of recon depth (shallow, medium, deep) to customize the extent of scanning.
    Subdomain Enumeration: Retrieves subdomains using crt.sh.
    Port Scanning: Identifies open ports using nmap.
    Directory Brute-Forcing: Discovers hidden directories using ffuf.
    Vulnerability Scanning: Checks for common vulnerabilities like SQL Injection (SQLi) and Cross-Site Scripting (XSS).
    Screenshot Capturing: Takes screenshots of discovered web applications using EyeWitness.
    Report Generation: Compiles findings into a comprehensive report.
    Modular Design: Although provided as a single script, the tool is structured for easy expansion and integration of additional features.

    
