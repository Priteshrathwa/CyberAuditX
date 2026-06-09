#!/usr/bin/env python3
"""
CyberAuditX - Main Application
Unified interface for security scanning tools
"""

import sys
import os
from scanner.nmap_scan import NmapScanner
from scanner.nikto_scan import NiktoScanner
from scanner.sqlmap_scan import SQLMapScanner


def print_banner():
    """Print application banner"""
    banner = "CyberAuditX"
    print(banner)


def check_tool_availability():
    """Check which scanning tools are available"""
    tools = {}
    
    # Check Nmap
    nmap_scanner = NmapScanner()
    try:
        import subprocess
        result = subprocess.run(['which', 'nmap'], capture_output=True, timeout=5)
        tools['nmap'] = result.returncode == 0
    except:
        tools['nmap'] = False
    
    # Check Nikto
    nikto_scanner = NiktoScanner()
    tools['nikto'] = nikto_scanner._check_nikto_installed()
    
    # Check SQLMap
    sqlmap_scanner = SQLMapScanner()
    tools['sqlmap'] = sqlmap_scanner._check_sqlmap_installed()
    
    return tools


def nmap_menu():
    """Nmap scanning menu"""
    print("\n" + "=" * 60)
    print("NMAP SCANNER")
    print("=" * 60)
    
    target = input("\nEnter target (IP/hostname): ").strip()
    if not target:
        print("[-] No target specified!")
        return
    
    print("\nScan Types:")
    print("1. Quick Scan (Fast)")
    print("2. Service Version Scan")
    print("3. Full Scan (Slow)")
    print("4. Custom Scan")
    
    choice = input("\nSelect scan type [1]: ").strip() or "1"
    
    scanner = NmapScanner()
    results = None
    
    if choice == "1":
        results = scanner.quick_scan(target)
    elif choice == "2":
        results = scanner.service_version_scan(target)
    elif choice == "3":
        results = scanner.full_scan(target)
    elif choice == "4":
        args = input("Enter nmap arguments: ").strip()
        results = scanner.custom_scan(target, args)
    else:
        print("[-] Invalid choice!")
        return
    
    if results and 'error' not in results:
        scanner.print_summary()
        
        save = input("\nSave results? (y/n) [y]: ").strip().lower() or 'y'
        if save == 'y':
            scanner.save_results(format='json')
            scanner.save_results(format='txt')
            print("[+] Results saved!")
    else:
        print(f"[-] Scan failed: {results.get('error', 'Unknown error')}")


def nikto_menu():
    """Nikto scanning menu"""
    print("\n" + "=" * 60)
    print("NIKTO SCANNER")
    print("=" * 60)
    
    target = input("\nEnter target URL (e.g., http://example.com): ").strip()
    if not target:
        print("[-] No target specified!")
        return
    
    print("\nScan Types:")
    print("1. Basic Scan (Recommended)")
    print("2. Full Scan")
    print("3. SSL Scan")
    print("4. Custom Scan")
    
    choice = input("\nSelect scan type [1]: ").strip() or "1"
    
    scanner = NiktoScanner()
    results = None
    
    if choice == "1":
        results = scanner.basic_scan(target)
    elif choice == "2":
        results = scanner.full_scan(target)
    elif choice == "3":
        results = scanner.ssl_scan(target)
    elif choice == "4":
        args = input("Enter nikto arguments: ").strip()
        results = scanner.custom_scan(target, args)
    else:
        print("[-] Invalid choice!")
        return
    
    if results and 'error' not in results:
        scanner.print_summary()
        
        save = input("\nSave results? (y/n) [y]: ").strip().lower() or 'y'
        if save == 'y':
            scanner.save_results(format='json')
            scanner.save_results(format='txt')
            print("[+] Results saved!")
    else:
        print(f"[-] Scan failed: {results.get('error', 'Unknown error')}")


def sqlmap_menu():
    """SQLMap scanning menu"""
    print("\n" + "=" * 60)
    print("SQLMAP SCANNER")
    print("=" * 60)
    
    target = input("\nEnter target URL (e.g., http://example.com/page.php?id=1): ").strip()
    if not target:
        print("[-] No target specified!")
        return
    
    print("\nScan Types:")
    print("1. Basic Scan (Recommended)")
    print("2. Deep Scan (Slow)")
    print("3. Database Enumeration")
    print("4. Form-based Scan")
    print("5. Custom Scan")
    
    choice = input("\nSelect scan type [1]: ").strip() or "1"
    
    scanner = SQLMapScanner()
    results = None
    
    if choice == "1":
        results = scanner.basic_scan(target)
    elif choice == "2":
        confirm = input("[!] Deep scan can take very long time. Continue? (y/n): ").strip().lower()
        if confirm == 'y':
            results = scanner.deep_scan(target)
        else:
            print("[*] Scan cancelled.")
            return
    elif choice == "3":
        results = scanner.scan_with_dbs(target)
    elif choice == "4":
        results = scanner.scan_with_forms(target)
    elif choice == "5":
        args = input("Enter SQLMap arguments: ").strip()
        results = scanner.custom_scan(target, args)
    else:
        print("[-] Invalid choice!")
        return
    
    if results and 'error' not in results:
        scanner.print_summary()
        
        save = input("\nSave results? (y/n) [y]: ").strip().lower() or 'y'
        if save == 'y':
            scanner.save_results(format='json')
            scanner.save_results(format='txt')
            print("[+] Results saved!")
    else:
        print(f"[-] Scan failed: {results.get('error', 'Unknown error')}")


def combined_scan():
    """Perform combined Nmap and Nikto scan"""
    print("\n" + "=" * 60)
    print("COMBINED SCAN (NMAP + NIKTO)")
    print("=" * 60)
    
    target = input("\nEnter target (IP/hostname): ").strip()
    if not target:
        print("[-] No target specified!")
        return
    
    # Step 1: Nmap scan
    print("\n[*] Step 1: Running Nmap scan...")
    nmap_scanner = NmapScanner()
    nmap_results = nmap_scanner.quick_scan(target)
    
    if 'error' in nmap_results:
        print(f"[-] Nmap scan failed: {nmap_results['error']}")
        return
    
    nmap_scanner.print_summary()
    nmap_scanner.save_results(format='json')
    
    # Check for web ports
    web_ports = []
    for host, host_info in nmap_results.get('hosts', {}).items():
        for port in host_info.get('ports', []):
            if port['state'] == 'open' and port['port'] in ['80', '443', '8080', '8443']:
                web_ports.append(port['port'])
    
    if not web_ports:
        print("\n[!] No web ports found. Skipping Nikto scan.")
        return
    
    print(f"\n[*] Found web ports: {', '.join(web_ports)}")
    
    # Step 2: Nikto scan
    proceed = input("\n[*] Step 2: Run Nikto scan on web ports? (y/n) [y]: ").strip().lower() or 'y'
    
    if proceed == 'y':
        for port in web_ports:
            protocol = 'https' if port in ['443', '8443'] else 'http'
            url = f"{protocol}://{target}:{port}"
            
            print(f"\n[*] Scanning {url}...")
            nikto_scanner = NiktoScanner()
            nikto_results = nikto_scanner.basic_scan(url)
            
            if 'error' not in nikto_results:
                nikto_scanner.print_summary()
                nikto_scanner.save_results(format='json')
            else:
                print(f"[-] Nikto scan failed: {nikto_results['error']}")
    
    print("\n[+] Combined scan completed!")


def main_menu():
    """Main application menu"""
    print_banner()
    
    # Check tool availability
    print("[*] Checking available tools...")
    tools = check_tool_availability()
    
    print("\nAvailable Tools:")
    print(f"  Nmap:   {'✓ Installed' if tools['nmap'] else '✗ Not found'}")
    print(f"  Nikto:  {'✓ Installed' if tools['nikto'] else '✗ Not found'}")
    print(f"  SQLMap: {'✓ Installed' if tools['sqlmap'] else '✗ Not found'}")
    
    if not any(tools.values()):
        print("\n[-] ERROR: No scanning tools available!")
        print("\nPlease install required tools:")
        print("  Ubuntu/Debian: sudo apt-get install nmap nikto sqlmap")
        print("  CentOS/RHEL: sudo yum install nmap nikto sqlmap")
        print("  macOS: brew install nmap nikto sqlmap")
        return
    
    while True:
        print("\n" + "=" * 60)
        print("MAIN MENU")
        print("=" * 60)
        print("1. Nmap Scan (Network/Port Scanner)")
        print("2. Nikto Scan (Web Vulnerability Scanner)")
        print("3. SQLMap Scan (SQL Injection Testing)")
        print("4. Combined Scan (Nmap + Nikto)")
        print("5. View Scan Results")
        print("6. Help")
        print("0. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            if tools['nmap']:
                nmap_menu()
            else:
                print("[-] Nmap is not installed!")
        
        elif choice == '2':
            if tools['nikto']:
                nikto_menu()
            else:
                print("[-] Nikto is not installed!")
        
        elif choice == '3':
            if tools['sqlmap']:
                sqlmap_menu()
            else:
                print("[-] SQLMap is not installed!")
        
        elif choice == '4':
            if tools['nmap'] and tools['nikto']:
                combined_scan()
            else:
                print("[-] Both Nmap and Nikto are required for combined scan!")
        
        elif choice == '5':
            view_results()
        
        elif choice == '6':
            show_help()
        
        elif choice == '0':
            print("\n[+] Goodbye!")
            break
        
        else:
            print("[-] Invalid option!")


def view_results():
    """View saved scan results"""
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    
    results_dir = 'scan_results'
    
    if not os.path.exists(results_dir):
        print("[-] No scan results directory found!")
        return
    
    files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
    
    if not files:
        print("[-] No scan results found!")
        return
    
    print(f"\nFound {len(files)} result file(s):")
    for i, file in enumerate(files, 1):
        file_path = os.path.join(results_dir, file)
        size = os.path.getsize(file_path)
        print(f"{i}. {file} ({size} bytes)")
    
    print(f"\n[*] Results are stored in: {os.path.abspath(results_dir)}")


def show_help():
    """Show help information"""
    print("\n" + "=" * 60)
    print("HELP")
    print("=" * 60)
    
    help_text = """
CyberAuditX - Security Scanning Tool

SCANNERS:
  Nmap:   Network scanner for port discovery and service detection
  Nikto:  Web server vulnerability scanner
  SQLMap: SQL injection vulnerability testing tool

USAGE:
  1. Select a scanner from the main menu
  2. Enter target (IP, hostname, or URL)
  3. Choose scan type
  4. View and save results

SCAN TYPES:
  Nmap Quick Scan:     Fast scan of top 100 ports
  Nmap Service Scan:   Detect service versions
  Nmap Full Scan:      Scan all 65535 ports (slow)
  
  Nikto Basic Scan:    Quick web vulnerability check
  Nikto Full Scan:     Comprehensive test suite
  Nikto SSL Scan:      HTTPS-specific testing
  
  SQLMap Basic Scan:   Test for SQL injection vulnerabilities
  SQLMap Deep Scan:    Comprehensive SQL injection testing (slow)
  SQLMap DB Enum:      Enumerate available databases

OUTPUT:
  Results are saved in 'scan_results/' directory in:
  - JSON format (structured data)
  - TXT format (human-readable)
  - RAW format (original tool output)

TIPS:
  - Always get permission before scanning
  - Use test targets: scanme.nmap.org, testphp.vulnweb.com
  - Some scans require root/sudo privileges
  - SQL injection testing may be illegal without authorization
  - Full/deep scans can take a long time

LEGAL & ETHICAL:
  ⚠️  Only test systems you own or have explicit permission to test
  ⚠️  Unauthorized security testing may be illegal
  ⚠️  Use responsibly and ethically

For more information, see README.md
"""
    print(help_text)


if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)
