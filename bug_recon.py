import subprocess
import requests
import os


def subdomain_enum(domain):
    print(f"[*] Enumerating subdomains for {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomains.add(entry['name_value'])
            return list(subdomains)
        else:
            print(f"[!] Failed to retrieve subdomains for {domain}")
            return []
    except Exception as e:
        print(f"[!] Error in subdomain enumeration: {e}")
        return []


def port_scan(domain):
    print(f"[*] Scanning ports for {domain}")
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
        print(f"[!] Error during port scanning: {e}")
        return []


def dir_bruteforce(domain, port, wordlist="wordlist.txt"):
    print(f"[*] Brute-forcing directories for {domain}:{port}")
    try:
        protocol = "https" if port == "443" else "http"
        url = f"{protocol}://{domain}:{port}"
        result = subprocess.run(
            ["ffuf", "-w", wordlist, "-u", f"{url}/FUZZ", "-t", "50", "-o", f"dir_{domain}_{port}.txt"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"[*] Directory brute-force results saved for {domain}:{port}")
        else:
            print(f"[!] No directories found for {domain}:{port}")
    except Exception as e:
        print(f"[!] Error in directory brute-forcing: {e}")


def vuln_scan(domain, port):
    print(f"[*] Scanning for vulnerabilities on {domain}:{port}")
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

    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"[+] Vulnerability found: {vuln}")
    else:
        print(f"[-] No vulnerabilities found for {domain}:{port}")

# this will take SS
def screenshot(domain_list):
    print(f"[*] Capturing screenshots for {len(domain_list)} subdomains")
    try:
        # Create file for EyeWitness input
        with open("domains.txt", "w") as f:
            for domain in domain_list:
                f.write(f"http://{domain}\n")

        subprocess.run(["eyewitness", "--web", "--input", "domains.txt", "--directory", "eyewitness_output"], check=True)
        print("[*] Screenshots saved in 'eyewitness_output' directory")
    except Exception as e:
        print(f"[!] Error capturing screenshots: {e}")

# Report generation function
def generate_report(domain, subdomains, open_ports):
    print(f"[*] Generating report for {domain}")
    with open(f"{domain}_report.txt", "w") as report:
        report.write(f"Bug Recon Report for {domain}\n")
        report.write(f"Subdomains Found:\n")
        for subdomain in subdomains:
            report.write(f"- {subdomain}\n")
        report.write(f"\nOpen Ports:\n")
        for port in open_ports:
            report.write(f"- {port}\n")
    print(f"[*] Report saved as {domain}_report.txt")

def bug_recon():
    print("BugRecon - Automated Bug Hunting Tool")
    domain = input("Enter the target domain (e.g., example.com): ").strip()

    recon_depth = input("Enter recon depth (shallow/medium/deep): ").strip().lower()
    
    if recon_depth not in ["shallow", "medium", "deep"]:
        print("[!] Invalid recon depth. Choose either 'shallow', 'medium', or 'deep'.")
        return

  
    subdomains = subdomain_enum(domain)
    if not subdomains:
        print("[!] No subdomains found. Aborting recon.")
        return

    if recon_depth == "shallow":
        generate_report(domain, subdomains, [])
        return


    open_ports = []
    for subdomain in subdomains:
        open_ports += port_scan(subdomain)


    if recon_depth == "medium":
        for subdomain in subdomains:
            for port in open_ports:
                dir_bruteforce(subdomain, port)
        generate_report(domain, subdomains, open_ports)
        return

  
    if recon_depth == "deep":
        for subdomain in subdomains:
            for port in open_ports:
                vuln_scan(subdomain, port)
                dir_bruteforce(subdomain, port)

        screenshot(subdomains)
        generate_report(domain, subdomains, open_ports)
        return

if __name__ == "__main__":
    bug_recon()
