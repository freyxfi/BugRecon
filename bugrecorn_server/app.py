import subprocess
import requests
import os
from fastapi import FastAPI, HTTPException, BackgroundTasks
from typing import List, Optional
from pydantic import BaseModel
from fastapi.responses import FileResponse

app = FastAPI()

class ReconRequest(BaseModel):
    domain: str
    recon_depth: str  # 'shallow', 'medium', or 'deep'

@app.post("/bugrecon/")
async def bug_recon(request: ReconRequest, background_tasks: BackgroundTasks):
    domain = request.domain.strip()
    recon_depth = request.recon_depth.strip().lower()

    if recon_depth not in ["shallow", "medium", "deep"]:
        raise HTTPException(status_code=400, detail="[!] Invalid recon depth. Choose either 'shallow', 'medium', or 'deep'.")

    subdomains = subdomain_enum(domain)
    if not subdomains:
        raise HTTPException(status_code=400, detail=f"[!] No subdomains found for {domain}. Aborting recon.")
    
    open_ports = []
    if recon_depth in ["medium", "deep"]:
        for subdomain in subdomains:
            open_ports += port_scan(subdomain)

    if recon_depth == "deep":
        # Perform vulnerability scanning and screenshots in the background
        background_tasks.add_task(deep_recon_tasks, subdomains, open_ports)
    
    # Generate report and return it for download
    report_file = generate_report(domain, subdomains, open_ports)
    return {"message": f"Recon complete for {domain}.", "report_file": report_file}


def subdomain_enum(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomains.add(entry['name_value'])
            return list(subdomains)
        else:
            return []
    except Exception as e:
        return []


def port_scan(domain):
    try:
        result = subprocess.run(
            ["nmap", "-p-", "-T4", domain, "-oG", "-"],
            capture_output=True,
            text=True
        )
        open_ports = []
        for line in result.stdout.splitlines():
            if "open" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                open_ports.append(port)
        return open_ports
    except Exception as e:
        return []


def dir_bruteforce(domain, port, wordlist="wordlist.txt"):
    protocol = "https" if port == "443" else "http"
    url = f"{protocol}://{domain}:{port}"
    try:
        result = subprocess.run(
            ["ffuf", "-w", wordlist, "-u", f"{url}/FUZZ", "-t", "50", "-o", f"dir_{domain}_{port}.txt"],
            capture_output=True,
            text=True
        )
    except Exception as e:
        pass


def vuln_scan(domain, port):
    vulnerabilities = []

    def check_sqli(url):
        test_url = f"{url}?id=1'"
        response = requests.get(test_url)
        if "syntax" in response.text.lower() or "error" in response.text.lower():
            vulnerabilities.append("Possible SQL Injection")

    def check_xss(url):
        payload = "<script>alert('XSS')</script>"
        response = requests.get(f"{url}?search={payload}")
        if payload in response.text:
            vulnerabilities.append("Possible XSS")

    protocol = "https" if port == "443" else "http"
    url = f"{protocol}://{domain}:{port}"
    check_sqli(url)
    check_xss(url)

    return vulnerabilities


def screenshot(domain_list):
    try:
        with open("domains.txt", "w") as f:
            for domain in domain_list:
                f.write(f"http://{domain}\n")

        subprocess.run(["eyewitness", "--web", "--input", "domains.txt", "--directory", "eyewitness_output"], check=True)
    except Exception as e:
        pass


def generate_report(domain, subdomains, open_ports):
    report_filename = f"{domain}_report.txt"
    with open(report_filename, "w") as report:
        report.write(f"Bug Recon Report for {domain}\n")
        report.write(f"Subdomains Found:\n")
        for subdomain in subdomains:
            report.write(f"- {subdomain}\n")
        report.write(f"\nOpen Ports:\n")
        for port in open_ports:
            report.write(f"- {port}\n")
    return report_filename


def deep_recon_tasks(subdomains, open_ports):
    for subdomain in subdomains:
        for port in open_ports:
            vuln_scan(subdomain, port)
            dir_bruteforce(subdomain, port)

    screenshot(subdomains)


@app.get("/download-report/{filename}")
async def download_report(filename: str):
    file_path = f"./{filename}"
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='application/octet-stream', filename=filename)
    else:
        raise HTTPException(status_code=404, detail="Report not found")


@app.get("/download-screenshots/")
async def download_screenshots():
    screenshots_dir = "./eyewitness_output"
    if os.path.exists(screenshots_dir):
        return FileResponse(screenshots_dir, media_type='application/zip', filename="screenshots.zip")
    else:
        raise HTTPException(status_code=404, detail="Screenshots not found")