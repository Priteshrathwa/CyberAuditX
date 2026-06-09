#!/usr/bin/env python3
"""
SQLMap Scanner Automation Script
Automates SQLMap SQL injection testing and collects output in structured format
"""

import subprocess
import json
import os
import re
from datetime import datetime


class SQLMapScanner:
    """Class to automate SQLMap scans and collect results"""
    
    def __init__(self, output_dir='scan_results'):
        """
        Initialize the SQLMap Scanner
        
        Args:
            output_dir (str): Directory to store scan results
        """
        self.output_dir = output_dir
        self.scan_results = {}
        self.raw_output = ""
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def _check_sqlmap_installed(self):
        """
        Check if SQLMap is installed on the system
        
        Returns:
            bool: True if SQLMap is installed, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', 'sqlmap'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return True
            
            # Check for sqlmap.py in common locations
            common_paths = [
                '/usr/share/sqlmap/sqlmap.py',
                '/usr/local/bin/sqlmap',
                'sqlmap.py'
            ]
            for path in common_paths:
                if os.path.exists(path):
                    return True
            
            return False
        except Exception:
            return False
    
    def _get_sqlmap_command(self):
        """
        Get the appropriate SQLMap command
        
        Returns:
            str: SQLMap command to use
        """
        # Try standard sqlmap command
        try:
            result = subprocess.run(['which', 'sqlmap'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return 'sqlmap'
        except:
            pass
        
        # Check common paths
        if os.path.exists('/usr/share/sqlmap/sqlmap.py'):
            return 'python3 /usr/share/sqlmap/sqlmap.py'
        elif os.path.exists('/usr/local/bin/sqlmap'):
            return '/usr/local/bin/sqlmap'
        
        return 'sqlmap'
    
    def _run_sqlmap_command(self, target, arguments):
        """
        Execute SQLMap command using subprocess
        
        Args:
            target (str): Target URL to scan
            arguments (str): SQLMap arguments
            
        Returns:
            tuple: (return_code, stdout, stderr)
        """
        try:
            sqlmap_cmd = self._get_sqlmap_command()
            
            # Build command
            if sqlmap_cmd.startswith('python'):
                cmd = sqlmap_cmd.split() + ['-u', target, '--batch'] + arguments.split()
            else:
                cmd = [sqlmap_cmd, '-u', target, '--batch'] + arguments.split()
            
            # Remove empty strings
            cmd = [c for c in cmd if c]
            
            print(f"[*] Executing: {' '.join(cmd)}")
            print(f"[!] Note: SQLMap scans may take several minutes...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            self.raw_output = result.stdout
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return -1, "", "Scan timed out after 1 hour"
        except FileNotFoundError:
            return -1, "", "sqlmap command not found. Please install SQLMap."
        except Exception as e:
            return -1, "", str(e)
    
    def _parse_output(self, output, target, scan_type):
        """
        Parse SQLMap output and structure results
        
        Args:
            output (str): Raw SQLMap output
            target (str): Scanned target
            scan_type (str): Type of scan performed
            
        Returns:
            dict: Structured scan results
        """
        results = {
            'scan_type': scan_type,
            'target': target,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'raw_output': output,
            'vulnerabilities': [],
            'injections': [],
            'databases': [],
            'tables': [],
            'summary': {
                'is_vulnerable': False,
                'injection_points': 0,
                'database_type': '',
                'total_databases': 0,
                'total_tables': 0
            }
        }
        
        # Parse output line by line
        for line in output.split('\n'):
            # Check if target is vulnerable
            if 'is vulnerable' in line.lower() or 'injectable' in line.lower():
                results['summary']['is_vulnerable'] = True
            
            # Extract database type
            if 'back-end DBMS:' in line or 'web application technology:' in line:
                match = re.search(r'DBMS:\s*(.+?)(?:\s+\d|\n|$)', line)
                if match:
                    results['summary']['database_type'] = match.group(1).strip()
            
            # Extract injection points
            if 'Parameter:' in line and 'is vulnerable' in output[output.find(line):output.find(line)+200].lower():
                match = re.search(r'Parameter:\s*(.+?)(?:\s+Type:|$)', line)
                if match:
                    param = match.group(1).strip()
                    results['vulnerabilities'].append({
                        'parameter': param,
                        'type': 'SQL Injection',
                        'severity': 'high'
                    })
                    results['summary']['injection_points'] += 1
            
            # Extract injection types
            if 'Type:' in line:
                match = re.search(r'Type:\s*(.+)', line)
                if match:
                    injection_type = match.group(1).strip()
                    if injection_type and injection_type not in results['injections']:
                        results['injections'].append(injection_type)
            
            # Extract databases
            if line.strip().startswith('[*]') and 'database' in line.lower():
                match = re.search(r'\[\*\]\s+(.+)', line)
                if match:
                    db_name = match.group(1).strip()
                    if db_name and db_name not in results['databases']:
                        results['databases'].append(db_name)
            
            # Extract tables
            if line.strip().startswith('[*]') and 'table' in line.lower():
                match = re.search(r'\[\*\]\s+(.+)', line)
                if match:
                    table_name = match.group(1).strip()
                    if table_name and table_name not in results['tables']:
                        results['tables'].append(table_name)
        
        results['summary']['total_databases'] = len(results['databases'])
        results['summary']['total_tables'] = len(results['tables'])
        
        return results
    
    def basic_scan(self, target):
        """
        Perform a basic SQLMap vulnerability scan
        
        Args:
            target (str): Target URL to scan
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting basic SQLMap scan on {target}...")
        returncode, stdout, stderr = self._run_sqlmap_command(target, '--level=1 --risk=1')
        
        # Check for actual errors (not just informational messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'critical', 'failed', 'unable to connect']):
            if 'not vulnerable' not in stdout.lower() and (not stdout or len(stdout) < 100):
                print(f"[-] Error during basic scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'basic_scan')
        self.scan_results = results
        print(f"[+] Basic scan completed for {target}")
        return results
    
    def deep_scan(self, target):
        """
        Perform a comprehensive deep scan
        
        Args:
            target (str): Target URL to scan
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting deep SQLMap scan on {target}...")
        print(f"[!] Warning: Deep scan may take a very long time")
        returncode, stdout, stderr = self._run_sqlmap_command(target, '--level=5 --risk=3')
        
        # Check for actual errors (not just informational messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'critical', 'failed', 'unable to connect']):
            if 'not vulnerable' not in stdout.lower() and (not stdout or len(stdout) < 100):
                print(f"[-] Error during deep scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'deep_scan')
        self.scan_results = results
        print(f"[+] Deep scan completed for {target}")
        return results
    
    def scan_with_dbs(self, target):
        """
        Scan and enumerate databases
        
        Args:
            target (str): Target URL to scan
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting SQLMap scan with database enumeration on {target}...")
        returncode, stdout, stderr = self._run_sqlmap_command(target, '--dbs --level=2 --risk=2')
        
        # Check for actual errors (not just informational messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'critical', 'failed', 'unable to connect']):
            if 'not vulnerable' not in stdout.lower() and (not stdout or len(stdout) < 100):
                print(f"[-] Error during database scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'database_scan')
        self.scan_results = results
        print(f"[+] Database scan completed for {target}")
        return results
    
    def scan_database_tables(self, target, database):
        """
        Enumerate tables in a specific database
        
        Args:
            target (str): Target URL to scan
            database (str): Database name to enumerate
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting table enumeration for database '{database}' on {target}...")
        returncode, stdout, stderr = self._run_sqlmap_command(
            target, 
            f'-D {database} --tables --level=2 --risk=2'
        )
        
        # Check for actual errors (not just informational messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'critical', 'failed', 'unable to connect']):
            if 'not vulnerable' not in stdout.lower() and (not stdout or len(stdout) < 100):
                print(f"[-] Error during table enumeration: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'table_scan')
        self.scan_results = results
        print(f"[+] Table enumeration completed for {target}")
        return results
    
    def scan_with_forms(self, target):
        """
        Scan and automatically parse forms
        
        Args:
            target (str): Target URL to scan
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting SQLMap scan with form parsing on {target}...")
        returncode, stdout, stderr = self._run_sqlmap_command(target, '--forms --level=2 --risk=2')
        
        # Check for actual errors (not just informational messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'critical', 'failed', 'unable to connect']):
            if 'not vulnerable' not in stdout.lower() and (not stdout or len(stdout) < 100):
                print(f"[-] Error during form scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'form_scan')
        self.scan_results = results
        print(f"[+] Form scan completed for {target}")
        return results
    
    def scan_crawl(self, target, depth=2):
        """
        Crawl website and test for SQL injection
        
        Args:
            target (str): Target URL to scan
            depth (int): Crawl depth (default: 2)
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting SQLMap crawl scan on {target} (depth: {depth})...")
        print(f"[!] Warning: Crawl scan may take a very long time")
        returncode, stdout, stderr = self._run_sqlmap_command(
            target, 
            f'--crawl={depth} --level=1 --risk=1'
        )
        
        # Check for actual errors (not just informational messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'critical', 'failed', 'unable to connect']):
            if 'not vulnerable' not in stdout.lower() and (not stdout or len(stdout) < 100):
                print(f"[-] Error during crawl scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'crawl_scan')
        self.scan_results = results
        print(f"[+] Crawl scan completed for {target}")
        return results
    
    def custom_scan(self, target, arguments):
        """
        Perform custom SQLMap scan with user-defined arguments
        
        Args:
            target (str): Target URL to scan
            arguments (str): Custom SQLMap arguments
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting custom SQLMap scan on {target} with arguments: {arguments}")
        returncode, stdout, stderr = self._run_sqlmap_command(target, arguments)
        
        # Check for actual errors (not just informational messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'critical', 'failed', 'unable to connect']):
            if 'not vulnerable' not in stdout.lower() and (not stdout or len(stdout) < 100):
                print(f"[-] Error during custom scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'custom_scan')
        self.scan_results = results
        print(f"[+] Custom scan completed for {target}")
        return results
    
    def save_results(self, filename=None, format='json'):
        """
        Save scan results to file
        
        Args:
            filename (str): Output filename (auto-generated if None)
            format (str): Output format ('json', 'txt', or 'raw')
            
        Returns:
            str: Path to saved file
        """
        if not self.scan_results:
            print("[-] No scan results to save")
            return None
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target = self.scan_results.get('target', 'unknown')
        # Clean target for filename
        target = target.replace('http://', '').replace('https://', '')
        target = target.replace('/', '_').replace(':', '_').replace('.', '_').replace('?', '_').replace('&', '_')
        scan_type = self.scan_results.get('scan_type', 'scan')
        
        if filename is None:
            filename = f"sqlmap_{scan_type}_{target}_{timestamp}"
        
        if format == 'json':
            filepath = os.path.join(self.output_dir, f"{filename}.json")
            with open(filepath, 'w') as f:
                json.dump(self.scan_results, f, indent=4)
            print(f"[+] Results saved to {filepath}")
            return filepath
        
        elif format == 'txt':
            filepath = os.path.join(self.output_dir, f"{filename}.txt")
            with open(filepath, 'w') as f:
                f.write(self._format_text_output())
            print(f"[+] Results saved to {filepath}")
            return filepath
        
        elif format == 'raw':
            filepath = os.path.join(self.output_dir, f"{filename}_raw.txt")
            with open(filepath, 'w') as f:
                f.write(self.raw_output)
            print(f"[+] Raw output saved to {filepath}")
            return filepath
        
        else:
            print(f"[-] Unsupported format: {format}")
            return None
    
    def _format_text_output(self):
        """
        Format results as human-readable text
        
        Returns:
            str: Formatted text output
        """
        output = []
        output.append("=" * 80)
        output.append("SQLMAP SCAN RESULTS")
        output.append("=" * 80)
        output.append(f"Scan Type: {self.scan_results.get('scan_type', 'N/A')}")
        output.append(f"Target: {self.scan_results.get('target', 'N/A')}")
        output.append(f"Timestamp: {self.scan_results.get('timestamp', 'N/A')}")
        output.append("=" * 80)
        output.append("")
        
        summary = self.scan_results.get('summary', {})
        output.append("SUMMARY:")
        output.append(f"  Vulnerable: {'YES' if summary.get('is_vulnerable') else 'NO'}")
        output.append(f"  Database Type: {summary.get('database_type', 'N/A')}")
        output.append(f"  Injection Points: {summary.get('injection_points', 0)}")
        output.append(f"  Databases Found: {summary.get('total_databases', 0)}")
        output.append(f"  Tables Found: {summary.get('total_tables', 0)}")
        output.append("")
        
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            output.append("VULNERABILITIES:")
            output.append("-" * 80)
            for i, vuln in enumerate(vulnerabilities, 1):
                output.append(f"\n{i}. Parameter: {vuln.get('parameter', 'N/A')}")
                output.append(f"   Type: {vuln.get('type', 'N/A')}")
                output.append(f"   Severity: {vuln.get('severity', 'N/A').upper()}")
        else:
            output.append("No vulnerabilities detected.")
        
        output.append("")
        
        injections = self.scan_results.get('injections', [])
        if injections:
            output.append("INJECTION TYPES DETECTED:")
            for injection in injections:
                output.append(f"  • {injection}")
            output.append("")
        
        databases = self.scan_results.get('databases', [])
        if databases:
            output.append("DATABASES FOUND:")
            for db in databases:
                output.append(f"  • {db}")
            output.append("")
        
        tables = self.scan_results.get('tables', [])
        if tables:
            output.append("TABLES FOUND:")
            for table in tables[:20]:  # Limit to first 20
                output.append(f"  • {table}")
            if len(tables) > 20:
                output.append(f"  ... and {len(tables) - 20} more tables")
            output.append("")
        
        output.append("=" * 80)
        output.append("RAW OUTPUT:")
        output.append("-" * 80)
        output.append(self.scan_results.get('raw_output', ''))
        output.append("=" * 80)
        
        return "\n".join(output)
    
    def print_summary(self):
        """Print a summary of the scan results"""
        if not self.scan_results:
            print("[-] No scan results available")
            return
        
        summary = self.scan_results.get('summary', {})
        
        print("\n" + "=" * 60)
        print("SQLMAP SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.scan_results.get('target', 'N/A')}")
        print(f"Scan Type: {self.scan_results.get('scan_type', 'N/A')}")
        print(f"Timestamp: {self.scan_results.get('timestamp', 'N/A')}")
        
        # Vulnerability status
        is_vulnerable = summary.get('is_vulnerable', False)
        status = "⚠️  VULNERABLE" if is_vulnerable else "✓ Not Vulnerable"
        print(f"\nStatus: {status}")
        
        if is_vulnerable:
            print(f"\nDatabase Type: {summary.get('database_type', 'Unknown')}")
            print(f"Injection Points Found: {summary.get('injection_points', 0)}")
        
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\nVulnerable Parameters:")
            for vuln in vulnerabilities:
                print(f"  • {vuln.get('parameter', 'N/A')} [{vuln.get('severity', 'N/A').upper()}]")
        
        injections = self.scan_results.get('injections', [])
        if injections:
            print(f"\nInjection Types:")
            for injection in injections:
                print(f"  • {injection}")
        
        databases = self.scan_results.get('databases', [])
        if databases:
            print(f"\nDatabases Found ({len(databases)}):")
            for db in databases[:5]:
                print(f"  • {db}")
            if len(databases) > 5:
                print(f"  ... and {len(databases) - 5} more")
        
        tables = self.scan_results.get('tables', [])
        if tables:
            print(f"\nTables Found: {len(tables)}")
        
        print("=" * 60 + "\n")


def main():
    """Main function to demonstrate usage"""
    print("=" * 60)
    print("SQLMAP SCANNER AUTOMATION")
    print("=" * 60)
    
    # Check if SQLMap is installed
    scanner = SQLMapScanner()
    if not scanner._check_sqlmap_installed():
        print("\n[-] ERROR: SQLMap is not installed on your system!")
        print("[*] To install SQLMap:")
        print("    Ubuntu/Debian: sudo apt-get install sqlmap")
        print("    CentOS/RHEL: sudo yum install sqlmap")
        print("    macOS: brew install sqlmap")
        print("    Or download from: https://github.com/sqlmapproject/sqlmap")
        return
    
    print("\n[+] SQLMap is installed!")
    
    # Get target from user
    target = input("\nEnter target URL (e.g., http://example.com/page.php?id=1): ").strip()
    
    if not target:
        print("[-] No target specified. Using test URL.")
        target = "http://testphp.vulnweb.com/artists.php?artist=1"
        print(f"[*] Using: {target}")
    
    # Display scan options
    print("\n" + "=" * 60)
    print("Scan Options:")
    print("=" * 60)
    print("1. Basic Scan (level 1, risk 1) - Recommended for first scan")
    print("2. Deep Scan (level 5, risk 3) - Comprehensive but slow")
    print("3. Database Enumeration (--dbs)")
    print("4. Table Enumeration (requires database name)")
    print("5. Form-based Scan (--forms)")
    print("6. Crawl and Scan (crawl website)")
    print("7. Custom Scan (specify your own arguments)")
    
    choice = input("\nSelect scan type (1-7) [default: 1]: ").strip() or "1"
    
    # Perform scan based on choice
    results = None
    
    if choice == '1':
        results = scanner.basic_scan(target)
    
    elif choice == '2':
        confirm = input("[!] Deep scan can take a very long time. Continue? (y/n): ").strip().lower()
        if confirm == 'y':
            results = scanner.deep_scan(target)
        else:
            print("[*] Scan cancelled.")
            return
    
    elif choice == '3':
        results = scanner.scan_with_dbs(target)
    
    elif choice == '4':
        database = input("Enter database name: ").strip()
        if database:
            results = scanner.scan_database_tables(target, database)
        else:
            print("[-] No database name provided.")
            return
    
    elif choice == '5':
        results = scanner.scan_with_forms(target)
    
    elif choice == '6':
        depth = input("Enter crawl depth (1-3) [default: 2]: ").strip() or "2"
        try:
            depth = int(depth)
            results = scanner.scan_crawl(target, depth)
        except ValueError:
            print("[-] Invalid depth. Using default: 2")
            results = scanner.scan_crawl(target, 2)
    
    elif choice == '7':
        print("\nCommon SQLMap arguments:")
        print("  --dbs                  List databases")
        print("  --tables               List tables")
        print("  --columns              List columns")
        print("  --dump                 Dump data")
        print("  --level=N              Test level (1-5)")
        print("  --risk=N               Risk level (1-3)")
        print("  --technique=TECH       SQL injection techniques")
        args = input("\nEnter custom SQLMap arguments: ").strip()
        if args:
            results = scanner.custom_scan(target, args)
        else:
            print("[-] No arguments provided. Using basic scan.")
            results = scanner.basic_scan(target)
    
    else:
        print("[-] Invalid choice. Using basic scan.")
        results = scanner.basic_scan(target)
    
    # Check for errors
    if results and 'error' in results:
        print(f"\n[-] Scan encountered an error: {results['error']}")
        if 'raw_output' in results and results['raw_output']:
            print("\n[*] Partial output (first 1000 chars):")
            print(results['raw_output'][:1000])
    else:
        # Print summary
        scanner.print_summary()
        
        # Save results
        save = input("\nWould you like to save the results? (y/n) [default: y]: ").strip().lower()
        if save in ['', 'y', 'yes']:
            print("\nSave format options:")
            print("1. JSON (structured data)")
            print("2. TXT (human-readable)")
            print("3. RAW (raw SQLMap output)")
            print("4. All formats")
            
            format_choice = input("Select format (1-4) [default: 1]: ").strip()
            
            if format_choice == '2':
                scanner.save_results(format='txt')
            elif format_choice == '3':
                scanner.save_results(format='raw')
            elif format_choice == '4':
                scanner.save_results(format='json')
                scanner.save_results(format='txt')
                scanner.save_results(format='raw')
            else:
                scanner.save_results(format='json')
    
    print("\n[+] Scan completed!")
    print("\n" + "=" * 60)
    print("IMPORTANT REMINDER:")
    print("  • Only test applications you have permission to test")
    print("  • SQL injection testing may be illegal without authorization")
    print("  • Use responsibly and ethically")
    print("=" * 60)


if __name__ == '__main__':
    main()
