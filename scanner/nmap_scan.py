#!/usr/bin/env python3
"""
Nmap Scanner Automation Script
Automates nmap scans and collects output in structured format
"""

import subprocess
import json
import os
import re
from datetime import datetime


class NmapScanner:
    """Class to automate nmap scans and collect results"""
    
    def __init__(self, output_dir='scan_results'):
        """
        Initialize the Nmap Scanner
        
        Args:
            output_dir (str): Directory to store scan results
        """
        self.output_dir = output_dir
        self.scan_results = {}
        self.raw_output = ""
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def _run_nmap_command(self, target, arguments):
        """
        Execute nmap command using subprocess
        
        Args:
            target (str): Target to scan
            arguments (str): Nmap arguments
            
        Returns:
            tuple: (return_code, stdout, stderr)
        """
        try:
            cmd = ['nmap'] + arguments.split() + [target]
            print(f"[*] Executing: {' '.join(cmd)}")
            
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
            return -1, "", "nmap command not found. Please install nmap."
        except Exception as e:
            return -1, "", str(e)
    
    def _parse_output(self, output, target, scan_type):
        """
        Parse nmap output and structure results
        
        Args:
            output (str): Raw nmap output
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
            'ports': [],
            'summary': {
                'total_ports': 0,
                'open_ports': 0
            }
        }
        
        # Parse port information: PORT STATE SERVICE VERSION
        for line in output.split('\n'):
            # Match port lines: 22/tcp open ssh OpenSSH 7.6p1
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?', line)
            if port_match:
                port_num = port_match.group(1)
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5).strip() if port_match.group(5) else ''
                
                port_info = {
                    'port': f"{port_num}/{protocol}",
                    'state': state,
                    'service': service,
                    'version': version
                }
                results['ports'].append(port_info)
                results['summary']['total_ports'] += 1
                
                if state == 'open':
                    results['summary']['open_ports'] += 1
        
        return results
    
    def scan(self, target):
        """
        Perform service version detection scan using: nmap -sV <target>
        
        Args:
            target (str): IP address or hostname to scan
            
        Returns:
            dict: Scan results with PORT, STATE, SERVICE, VERSION
        """
        print(f"[*] Starting nmap -sV scan on {target}...")
        returncode, stdout, stderr = self._run_nmap_command(target, '-sV')
        
        # Check for actual errors (not just warnings)
        if stderr and any(err in stderr.lower() for err in ['error', 'failed', 'cannot', 'unable', 'permission denied']):
            if not stdout or len(stdout) < 100:
                print(f"[-] Error during scan: {stderr}")
                return {'error': stderr, 'raw_output': stdout}
        
        results = self._parse_output(stdout, target, 'service_version_scan')
        self.scan_results = results
        print(f"[+] Nmap scan completed for {target}")
        return results
        
        results = self._parse_output(stdout, target, 'aggressive_scan')
        self.scan_results = results
        print(f"[+] Aggressive scan completed for {target}")
        return results
    
    def custom_scan(self, target, arguments):
        """
        Perform custom scan with user-defined arguments
        
        Args:
            target (str): IP address or hostname to scan
            arguments (str): Custom nmap arguments
            
        Returns:
            dict: Scan results
        """
        print(f"[*] Starting custom scan on {target} with arguments: {arguments}")
        returncode, stdout, stderr = self._run_nmap_command(target, arguments)
        
        # Check for actual errors (not just warnings)
        if stderr and any(err in stderr.lower() for err in ['error', 'failed', 'cannot', 'unable', 'permission denied']):
            if not stdout or len(stdout) < 100:
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
        target = self.scan_results.get('target', 'unknown').replace('.', '_').replace(' ', '_')
        scan_type = self.scan_results.get('scan_type', 'scan')
        
        if filename is None:
            filename = f"{scan_type}_{target}_{timestamp}"
        
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
        output.append(f"NMAP SCAN RESULTS")
        output.append("=" * 80)
        output.append(f"Scan Type: {self.scan_results.get('scan_type', 'N/A')}")
        output.append(f"Target: {self.scan_results.get('target', 'N/A')}")
        output.append(f"Timestamp: {self.scan_results.get('timestamp', 'N/A')}")
        output.append("=" * 80)
        output.append("")
        
        summary = self.scan_results.get('summary', {})
        output.append(f"Total Ports: {summary.get('total_ports', 0)}")
        output.append(f"Open Ports: {summary.get('open_ports', 0)}")
        output.append("")
        
        ports = self.scan_results.get('ports', [])
        if ports:
            output.append(f"{'PORT':<15} {'STATE':<10} {'SERVICE':<20} {'VERSION'}")
            output.append(f"{'-'*80}")
            
            for port in ports:
                version = port.get('version', '')
                output.append(f"{port['port']:<15} {port['state']:<10} "
                            f"{port['service']:<20} {version}")
            output.append("")
        
        output.append("=" * 80)
        output.append("\nRAW OUTPUT:")
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
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.scan_results.get('target', 'N/A')}")
        print(f"Scan Type: Service Version Detection (nmap -sV)")
        print(f"Timestamp: {self.scan_results.get('timestamp', 'N/A')}")
        print(f"\nTotal Ports: {summary.get('total_ports', 0)}")
        print(f"Open Ports: {summary.get('open_ports', 0)}")
        
        ports = self.scan_results.get('ports', [])
        open_ports = [p for p in ports if p['state'] == 'open']
        
        if open_ports:
            print(f"\nPORT            STATE      SERVICE              VERSION")
            print("-" * 60)
            for port in open_ports[:10]:  # Show first 10 open ports
                version = port.get('version', '')
                print(f"{port['port']:<15} {port['state']:<10} {port['service']:<20} {version}")
            if len(open_ports) > 10:
                print(f"\n... and {len(open_ports) - 10} more ports")
        
        print("=" * 60 + "\n")


def main():
    """Main function to demonstrate usage"""
    print("=" * 60)
    print("NMAP SCANNER AUTOMATION")
    print("Command: nmap -sV <target>")
    print("=" * 60)
    
    # Example usage
    scanner = NmapScanner()
    
    # Get target from user
    target = input("\nEnter target IP or hostname (e.g., scanme.nmap.org): ").strip()
    
    if not target:
        print("[-] No target specified. Using default: scanme.nmap.org")
        target = "scanme.nmap.org"
    
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
