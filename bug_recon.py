import subprocess
import requests
import os
import argparse
import json

LOGO = r"""
██████╗ ██╗   ██╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝██║   ██║██║  ███╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██║   ██║██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                    [ Created by Frey ]
         [ Automate your bug hunting process ]
"""

def subdomain_enum(domain):
    print(f"[*] Enumerating subdomains for {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            subdomains = set()
            if response.content.strip():  # Check for non-empty response
                json_response = json.loads(response.content)
                for entry in json_response:
                    subdomains.add(entry['name_value'].replace("*.",""))
                return sorted(list(subdomains))
            else:
                print(f"[!] No valid JSON response from crt.sh for {domain}")
                return []
        else:
            print(f"[!] Failed to retrieve subdomains for {domain}")
            return []
    except Exception as e:
        print(f"[!] Error in subdomain enumeration: {e}")
        return []

def save_subdomains(subdomains, output_file):
    try:
        with open(output_file, "w") as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        print(f"[*] Subdomains saved to {output_file}")
    except Exception as e:
        print(f"[!] Error saving subdomains: {e}")

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

def dir_bruteforce(domain, port, wordlist="wordlist.txt", threads="50"):
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

def screenshot(domain_list):
    print(f"[*] Capturing screenshots for {len(domain_list)} subdomains")
    try:
        with open("domains.txt", "w") as f:
            for domain in domain_list:
                f.write(f"http://{domain}\n")

        subprocess.run(["eyewitness", "--web", "--input", "domains.txt", "--directory", "eyewitness_output"], check=True)
        print("[*] Screenshots saved in 'eyewitness_output' directory")
    except Exception as e:
        print(f"[!] Error capturing screenshots: {e}")

def generate_report(domain, subdomains, open_ports, output_dir):
    output_path = os.path.join(output_dir, f"{domain}_report.txt")
    print(f"[*] Generating report for {domain} at {output_path}")
    with open(output_path, "w") as report:
        report.write(f"Bug Recon Report for {domain}\n")
        report.write(f"Subdomains Found:\n")
        for subdomain in subdomains:
            report.write(f"- {subdomain}\n")
        report.write(f"\nOpen Ports:\n")
        for port in open_ports:
            report.write(f"- {port}\n")
    print(f"[*] Report saved as {output_path}")

def bug_recon(domain, recon_depth, output_file, output_dir, threads):
    print(LOGO)
    print(f"BugRecon - Automated Bug Hunting Tool on {domain} with {recon_depth} depth")

    subdomains = subdomain_enum(domain)
    if not subdomains:
        print("[!] No subdomains found. Aborting recon.")
        return

    save_subdomains(subdomains, output_file)

    open_ports = []
    for subdomain in subdomains:
        open_ports += port_scan(subdomain)

    if recon_depth == "shallow":
        generate_report(domain, subdomains, [], output_dir)
        return

    if recon_depth == "medium":
        for subdomain in subdomains:
            for port in open_ports:
                dir_bruteforce(subdomain, port, threads=threads)
        generate_report(domain, subdomains, open_ports, output_dir)
        return

    if recon_depth == "deep":
        for subdomain in subdomains:
            for port in open_ports:
                vuln_scan(subdomain, port)
                dir_bruteforce(subdomain, port, threads=threads)

        screenshot(subdomains)
        generate_report(domain, subdomains, open_ports, output_dir)
        return

def help_menu():
    print(LOGO)
    help_text = """
    Usage: python bug_recon.py -d <domain> -r <recon_depth> -o <output_directory> -t <threads>

    Options:
    -h, --help          Show this help message and exit
    -d, --domain        Target domain for bug reconnaissance (required)
    -r, --recon-depth   Reconnaissance depth: shallow, medium, deep (required)
    -o, --output-file   Output file for saving subdomains (default: subdomains.txt)
    -t, --threads       Number of threads for brute-forcing directories (default: 50)
    """
    print(help_text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-d', '--domain', type=str, required=True, help="Target domain for bug reconnaissance")
    parser.add_argument('-r', '--recon-depth', type=str, required=True, choices=['shallow', 'medium', 'deep'], help="Reconnaissance depth: shallow, medium, deep")
    parser.add_argument('-o', '--output-file', type=str, default="subdomains.txt", help="Output file for saving subdomains (default: subdomains.txt)")
    parser.add_argument('-t', '--threads', type=str, default="50", help="Number of threads for brute-forcing directories (default: 50)")
    parser.add_argument('-h', '--help', action='store_true', help="Show help message")

    args = parser.parse_args()

    if args.help:
        help_menu()
    else:
        bug_recon(args.domain, args.recon_depth, args.output_file, ".", args.threads)
