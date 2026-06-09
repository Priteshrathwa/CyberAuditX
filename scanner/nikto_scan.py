#!/usr/bin/env python3
"""
Nikto Scanner Automation Script
Automates Nikto web server scans and collects output in structured format
"""

import subprocess
import json
import os
import re
from urllib.parse import urlparse
from datetime import datetime


class NiktoScanner:
    """Class to automate Nikto scans and collect results"""
    
    def __init__(self, output_dir='scan_results'):
        """
        Initialize the Nikto Scanner
        
        Args:
            output_dir (str): Directory to store scan results
        """
        self.output_dir = output_dir
        self.scan_results = {}
        self.raw_output = ""
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def _check_nikto_installed(self):
        """
        Check if Nikto is installed on the system
        
        Returns:
            bool: True if Nikto is installed, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', 'nikto'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _run_nikto_command(self, target, arguments):
        """
        Execute Nikto command using subprocess
        
        Args:
            target (str): Target URL or host to scan
            arguments (str): Nikto arguments
            
        Returns:
            tuple: (return_code, stdout, stderr)
        """
        try:
            # Build command
            cmd = ['nikto', '-h', target] + arguments.split()
            print(f"[*] Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            self.raw_output = result.stdout
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return -1, "", "Scan timed out"
        except FileNotFoundError:
            return -1, "", "nikto command not found. Please install Nikto."
        except Exception as e:
            return -1, "", str(e)
    
    def _parse_output(self, output, target, scan_type):
        """
        Parse Nikto output and structure results
        
        Args:
            output (str): Raw Nikto output
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
            'findings': [],
            'summary': {
                'total_items_found': 0,
                'server_info': '',
                'target_ip': '',
                'target_port': ''
            }
        }
        
        findings = []
        
        # Parse output line by line
        for line in output.split('\n'):
            # Extract server information
            if 'Server:' in line and not results['summary']['server_info']:
                match = re.search(r'Server:\s+(.+)', line)
                if match:
                    results['summary']['server_info'] = match.group(1).strip()
            
            # Extract target IP
            if 'Target IP:' in line or 'Target Host:' in line:
                match = re.search(r'(?:Target IP|Target Host):\s+(\S+)', line)
                if match:
                    results['summary']['target_ip'] = match.group(1).strip()
            
            # Extract target port
            if 'Target Port:' in line:
                match = re.search(r'Target Port:\s+(\d+)', line)
                if match:
                    results['summary']['target_port'] = match.group(1).strip()
            
            # Parse findings (lines starting with + )
            if line.strip().startswith('+ '):
                finding = line.strip()[2:].strip()
                if finding and finding not in ['Start Time:', 'End Time:']:
                    findings.append({
                        'description': finding,
                        'severity': self._determine_severity(finding)
                    })
        
        results['findings'] = findings
        results['summary']['total_items_found'] = len(findings)
        
        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        results['summary']['by_severity'] = severity_counts
        results['summary']['total_findings'] = len(findings)
        
        return results
    
    def _determine_severity(self, finding):
        """
        Determine severity level based on finding description
        
        Args:
            finding (str): Finding description
            
        Returns:
            str: Severity level (critical, high, medium, low, info)
        """
        finding_lower = finding.lower()
        
        # Critical indicators
        if any(word in finding_lower for word in ['shell', 'backdoor', 'malware', 'exploit', 'injection']):
            return 'critical'
        
        # High indicators
        if any(word in finding_lower for word in ['vulnerable', 'password', 'authentication', 'bypass', 'disclosure']):
            return 'high'
        
        # Medium indicators
        if any(word in finding_lower for word in ['outdated', 'deprecated', 'default', 'misconfiguration']):
            return 'medium'
        
        # Low indicators
        if any(word in finding_lower for word in ['cookie', 'header', 'options']):
            return 'low'
        
        # Default to info
        return 'info'
    
    def scan(self, target):
        """
        Perform Nikto scan using: nikto -h <target> -Tuning 123bde -maxtime 120s
        
        Args:
            target (str): Target URL or hostname (e.g., http://example.com or example.com)
            
        Returns:
            dict: Scan results
        """
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        print(f"[*] Starting Nikto scan on {target}...")
        returncode, stdout, stderr = self._run_nikto_command(
            target,
            '-Tuning 123bde -maxtime 120s -ask no'
        )
        
        # Check for actual errors (not just stderr messages)
        if stderr and any(err in stderr.lower() for err in ['error', 'failed', 'cannot', 'unable']):
            if not stdout or len(stdout) < 100:
                print(f"[-] Error during scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'nikto_scan')
        self.scan_results = results
        print(f"[+] Nikto scan completed for {target}")
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
        target = target.replace('/', '_').replace(':', '_').replace('.', '_')
        scan_type = self.scan_results.get('scan_type', 'scan')
        
        if filename is None:
            filename = f"nikto_{scan_type}_{target}_{timestamp}"
        
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
        output.append("NIKTO SCAN RESULTS")
        output.append("=" * 80)
        output.append(f"Scan Type: {self.scan_results.get('scan_type', 'N/A')}")
        output.append(f"Target: {self.scan_results.get('target', 'N/A')}")
        output.append(f"Timestamp: {self.scan_results.get('timestamp', 'N/A')}")
        output.append("=" * 80)
        output.append("")
        
        summary = self.scan_results.get('summary', {})
        output.append("SUMMARY:")
        output.append(f"  Server: {summary.get('server_info', 'N/A')}")
        output.append(f"  Target IP: {summary.get('target_ip', 'N/A')}")
        output.append(f"  Target Port: {summary.get('target_port', 'N/A')}")
        output.append(f"  Total Items Found: {summary.get('total_items_found', 0)}")
        output.append("")
        
        findings = self.scan_results.get('findings', [])
        if findings:
            # Group by severity
            severity_groups = {}
            for finding in findings:
                severity = finding['severity']
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(finding['description'])
            
            output.append("FINDINGS BY SEVERITY:")
            output.append("-" * 80)
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_groups:
                    output.append(f"\n[{severity.upper()}] ({len(severity_groups[severity])} items)")
                    for desc in severity_groups[severity]:
                        output.append(f"  • {desc}")
        else:
            output.append("No findings detected.")
        
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
        print("NIKTO SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.scan_results.get('target', 'N/A')}")
        print(f"Scan Type: {self.scan_results.get('scan_type', 'N/A')}")
        print(f"Timestamp: {self.scan_results.get('timestamp', 'N/A')}")
        print(f"\nServer: {summary.get('server_info', 'N/A')}")
        print(f"Target IP: {summary.get('target_ip', 'N/A')}")
        print(f"Target Port: {summary.get('target_port', 'N/A')}")
        print(f"\nTotal Items Found: {summary.get('total_items_found', 0)}")
        
        # Count by severity
        findings = self.scan_results.get('findings', [])
        if findings:
            severity_counts = {}
            for finding in findings:
                severity = finding['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print("\nFindings by Severity:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_counts:
                    print(f"  {severity.upper()}: {severity_counts[severity]}")
            
            print(f"\nTop Findings (first 5):")
            for i, finding in enumerate(findings[:5], 1):
                desc = finding['description']
                if len(desc) > 70:
                    desc = desc[:67] + "..."
                print(f"  {i}. [{finding['severity'].upper()}] {desc}")
            
            if len(findings) > 5:
                print(f"  ... and {len(findings) - 5} more findings")
        
        print("=" * 60 + "\n")


def main():
    """Main function to demonstrate usage"""
    print("=" * 60)
    print("NIKTO SCANNER AUTOMATION")
    print("Format: nikto -h <target> -Tuning 123bde -maxtime 120s")
    print("=" * 60)
    
    # Check if Nikto is installed
    scanner = NiktoScanner()
    if not scanner._check_nikto_installed():
        print("\n[-] ERROR: Nikto is not installed on your system!")
        print("[*] To install Nikto:")
        print("    Ubuntu/Debian: sudo apt-get install nikto")
        print("    CentOS/RHEL: sudo yum install nikto")
        print("    macOS: brew install nikto")
        return
    
    # Get target from user
    target = input("\nEnter target URL or hostname (e.g., http://example.com): ").strip()
    
    if not target:
        print("[-] No target specified. Using default: http://testphp.vulnweb.com")
        target = "http://testphp.vulnweb.com"
    
    # Perform scan
    results = scanner.scan(target)
    
    # Check for errors
    if results and 'error' in results:
        print(f"\n[-] Scan encountered an error: {results['error']}")
        if 'raw_output' in results and results['raw_output']:
            print("\n[*] Partial output:")
            print(results['raw_output'][:500])
    else:
        # Print summary
        scanner.print_summary()
        
        # Save results
        save = input("\nWould you like to save the results? (y/n) [default: y]: ").strip().lower()
        if save in ['', 'y', 'yes']:
            scanner.save_results(format='json')
    
    print("\n[+] Scan completed!")


if __name__ == '__main__':
    main()
