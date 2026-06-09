#!/usr/bin/env python3
"""
CyberAuditX Web Application
Web interface for automated security scanning tools
"""

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, Response, stream_with_context
from scanner.nmap_scan import NmapScanner
from scanner.nikto_scan import NiktoScanner
from scanner.sqlmap_scan import SQLMapScanner
from ai_analyzer import gemini_analyzer
import os
import json
from datetime import datetime
import subprocess
import time
import queue
import threading
from urllib.parse import urlparse, urlunparse

app = Flask(__name__)
app.secret_key = 'cyberauditx_secret_key_change_in_production'

# Initialize scanners
nmap_scanner = NmapScanner()
nikto_scanner = NiktoScanner()
sqlmap_scanner = SQLMapScanner()

# Store recent scans in memory (in production, use a database)
recent_scans = []

# Store active scan queues for live updates
active_scans = {}


def check_tool_availability():
    """Check if required tools are installed"""
    tools = {
        'nmap': False,
        'nikto': False,
        'sqlmap': False
    }
    
    for tool in tools.keys():
        try:
            result = subprocess.run(['which', tool], capture_output=True, text=True, timeout=5)
            tools[tool] = result.returncode == 0
        except Exception:
            tools[tool] = False
    
    return tools


@app.route('/')
def index():
    """Home page"""
    tools_status = check_tool_availability()
    return render_template('index.html', tools=tools_status, recent_scans=recent_scans[-10:])


@app.route('/nmap')
def nmap_page():
    """Nmap scanner page"""
    return render_template('nmap.html')


@app.route('/nikto')
def nikto_page():
    """Nikto scanner page"""
    return render_template('nikto.html')


@app.route('/sqlmap')
def sqlmap_page():
    """SQLMap scanner page"""
    return render_template('sqlmap.html')


@app.route('/automated')
def automated_page():
    """Automated combined scanning page"""
    return render_template('automated.html')


@app.route('/scan/nmap', methods=['POST'])
def nmap_scan():
    """Execute Nmap scan"""
    try:
        target = request.form.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Sanitize target: extract only host and port for Nmap (remove path/query)
        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.hostname or target.split('/')[0]
        port = parsed.port
        nmap_target = f"{host}:{port}" if port else host
        
        # Execute scan using: nmap -sV <target>
        results = nmap_scanner.scan(nmap_target)
        
        if 'error' in results:
            return jsonify({'error': results['error']}), 500
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"nmap_{timestamp}"
        filepath = nmap_scanner.save_results(filename, format='json')
        
        # Add to recent scans
        recent_scans.append({
            'tool': 'Nmap',
            'target': nmap_target,
            'scan_type': 'service_version',
            'timestamp': results.get('timestamp'),
            'filepath': filepath
        })
        
        return jsonify({
            'success': True,
            'results': results,
            'filepath': filepath
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/scan/nikto', methods=['POST'])
def nikto_scan():
    """Execute Nikto scan"""
    try:
        target = request.form.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Execute scan using: nikto -h <target> -Tuning 123bde -maxtime 120s
        results = nikto_scanner.scan(target)
        
        if 'error' in results:
            return jsonify({'error': results['error']}), 500
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"nikto_{timestamp}"
        filepath = nikto_scanner.save_results(filename, format='json')
        
        # Add to recent scans
        recent_scans.append({
            'tool': 'Nikto',
            'target': target,
            'scan_type': 'standard',
            'timestamp': results.get('timestamp'),
            'filepath': filepath
        })
        
        return jsonify({
            'success': True,
            'results': results,
            'filepath': filepath
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/scan/sqlmap', methods=['POST'])
def sqlmap_scan():
    """Execute SQLMap scan"""
    try:
        target = request.form.get('target')
        scan_type = request.form.get('scan_type', 'basic')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Execute scan based on type
        if scan_type == 'basic':
            results = sqlmap_scanner.basic_scan(target)
        elif scan_type == 'deep':
            results = sqlmap_scanner.deep_scan(target)
        elif scan_type == 'dbs':
            results = sqlmap_scanner.scan_with_dbs(target)
        elif scan_type == 'forms':
            results = sqlmap_scanner.scan_with_forms(target)
        elif scan_type == 'crawl':
            depth = request.form.get('depth', '2')
            results = sqlmap_scanner.scan_crawl(target, depth)
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        if 'error' in results:
            return jsonify({'error': results['error']}), 500
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"sqlmap_{scan_type}_{timestamp}"
        filepath = sqlmap_scanner.save_results(filename, format='json')
        
        # Add to recent scans
        recent_scans.append({
            'tool': 'SQLMap',
            'target': target,
            'scan_type': scan_type,
            'timestamp': results.get('timestamp'),
            'filepath': filepath
        })
        
        return jsonify({
            'success': True,
            'results': results,
            'filepath': filepath
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/results/<path:filename>')
def view_results(filename):
    """View saved scan results"""
    try:
        filepath = os.path.join('scan_results', filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        with open(filepath, 'r') as f:
            if filename.endswith('.json'):
                results = json.load(f)
                return render_template('results.html', results=results, filename=filename)
            else:
                content = f.read()
                return render_template('results_text.html', content=content, filename=filename)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/download/<path:filename>')
def download_results(filename):
    """Download scan results file"""
    try:
        filepath = os.path.join('scan_results', filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(filepath, as_attachment=True)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/recent-scans')
def api_recent_scans():
    """API endpoint for recent scans"""
    return jsonify(recent_scans[-20:])


def _normalize_targets(target: str):
    """Return (nmap_target, url_target) where nmap gets host[:port] and URL keeps path."""
    parsed = urlparse(target if '://' in target else f'http://{target}')
    host = parsed.hostname or target
    port = parsed.port
    nmap_target = f"{host}:{port}" if host and port else host
    # Rebuild canonical URL preserving path/query when provided
    scheme = parsed.scheme or 'http'
    netloc = f"{host}:{port}" if port else host
    url_target = urlunparse((scheme, netloc, parsed.path or '', '', parsed.query, parsed.fragment))
    return nmap_target, url_target


def run_automated_scan(scan_id, target, message_queue):
    """Run automated scan sequence: Nmap → SQLMap → Nikto"""
    try:
        nmap_target, url_target = _normalize_targets(target)
        all_results = {
            'scan_id': scan_id,
            'target': url_target,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'nmap': None,
            'sqlmap': None,
            'nikto': None,
            'vulnerabilities': []
        }
        
        # Step 1: Nmap Scan
        message_queue.put(json.dumps({
            'type': 'status',
            'step': 'nmap',
            'message': f'Starting Nmap port scan on {nmap_target} (normalized)'
        }))
        
        nmap_scanner_instance = NmapScanner()
        nmap_results = nmap_scanner_instance.scan(nmap_target)
        all_results['nmap'] = nmap_results
        
        if 'error' not in nmap_results:
            # Extract open ports
            open_ports = []
            for port_info in nmap_results.get('ports', []):
                if port_info.get('state') == 'open':
                    port_num = port_info.get('port', '').split('/')[0]
                    open_ports.append(port_num)
                    message_queue.put(json.dumps({
                        'type': 'vulnerability',
                        'severity': 'info',
                        'tool': 'nmap',
                        'message': f"Open port found: {port_info.get('port')} - {port_info.get('service')} {port_info.get('version')}"
                    }))
            
            message_queue.put(json.dumps({
                'type': 'status',
                'step': 'nmap',
                'message': f'Nmap scan completed. Found {len(open_ports)} open ports.'
            }))
        else:
            message_queue.put(json.dumps({
                'type': 'error',
                'step': 'nmap',
                'message': f"Nmap scan failed: {nmap_results.get('error')}"
            }))
        
        time.sleep(1)
        
        # Step 2: SQLMap Scan (if target is a URL)
        if url_target.startswith('http://') or url_target.startswith('https://'):
            message_queue.put(json.dumps({
                'type': 'status',
                'step': 'sqlmap',
                'message': 'Starting SQLMap injection scan...'
            }))
            
            sqlmap_scanner_instance = SQLMapScanner()
            sqlmap_results = sqlmap_scanner_instance.basic_scan(url_target)
            all_results['sqlmap'] = sqlmap_results
            
            if 'error' not in sqlmap_results:
                vulns = sqlmap_results.get('vulnerabilities', [])
                if vulns:
                    for vuln in vulns:
                        message_queue.put(json.dumps({
                            'type': 'vulnerability',
                            'severity': 'critical',
                            'tool': 'sqlmap',
                            'message': f"SQL Injection found in parameter: {vuln.get('parameter')} - Type: {vuln.get('type')}"
                        }))
                        all_results['vulnerabilities'].append({
                            'tool': 'SQLMap',
                            'severity': 'critical',
                            'description': f"SQL Injection in {vuln.get('parameter')}"
                        })
                
                message_queue.put(json.dumps({
                    'type': 'status',
                    'step': 'sqlmap',
                    'message': f'SQLMap scan completed. Found {len(vulns)} SQL injection vulnerabilities.'
                }))
            else:
                message_queue.put(json.dumps({
                    'type': 'error',
                    'step': 'sqlmap',
                    'message': f"SQLMap scan failed: {sqlmap_results.get('error')}"
                }))
        else:
            message_queue.put(json.dumps({
                'type': 'status',
                'step': 'sqlmap',
                'message': 'Skipping SQLMap (target is not a URL)'
            }))
        
        time.sleep(1)
        
        # Step 3: Nikto Scan (if target is a URL or has web ports)
        if url_target.startswith('http://') or url_target.startswith('https://'):
            nikto_target = url_target
        else:
            # Check if port 80 or 443 is open
            nikto_target = None
            if 'nmap' in all_results and all_results['nmap']:
                for port_info in all_results['nmap'].get('ports', []):
                    port_num = port_info.get('port', '').split('/')[0]
                    if port_num in ['80', '443'] and port_info.get('state') == 'open':
                        protocol = 'https' if port_num == '443' else 'http'
                        nikto_target = f"{protocol}://{nmap_target}"
                        break
        
        if nikto_target:
            message_queue.put(json.dumps({
                'type': 'status',
                'step': 'nikto',
                'message': f'Starting Nikto web vulnerability scan on {nikto_target}...'
            }))
            
            nikto_scanner_instance = NiktoScanner()
            nikto_results = nikto_scanner_instance.scan(nikto_target)
            all_results['nikto'] = nikto_results
            
            if 'error' not in nikto_results:
                findings = nikto_results.get('findings', [])
                critical_high = [f for f in findings if f.get('severity') in ['critical', 'high']]
                
                for finding in critical_high:
                    message_queue.put(json.dumps({
                        'type': 'vulnerability',
                        'severity': finding.get('severity'),
                        'tool': 'nikto',
                        'message': f"{finding.get('severity').upper()}: {finding.get('description')[:100]}"
                    }))
                    all_results['vulnerabilities'].append({
                        'tool': 'Nikto',
                        'severity': finding.get('severity'),
                        'description': finding.get('description')
                    })
                
                message_queue.put(json.dumps({
                    'type': 'status',
                    'step': 'nikto',
                    'message': f'Nikto scan completed. Found {len(findings)} issues ({len(critical_high)} critical/high).'
                }))
            else:
                message_queue.put(json.dumps({
                    'type': 'error',
                    'step': 'nikto',
                    'message': f"Nikto scan failed: {nikto_results.get('error')}"
                }))
        else:
            message_queue.put(json.dumps({
                'type': 'status',
                'step': 'nikto',
                'message': 'Skipping Nikto (no web service detected)'
            }))
        
        # Save combined results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"automated_scan_{url_target.replace('://', '_').replace('/', '_').replace('.', '_')}_{timestamp}.json"
        filepath = os.path.join('scan_results', filename)
        with open(filepath, 'w') as f:
            json.dump(all_results, f, indent=4)
        
        message_queue.put(json.dumps({
            'type': 'complete',
            'message': 'All scans completed!',
            'results': all_results,
            'filepath': filename
        }))
        
        # Add to recent scans
        recent_scans.append({
            'tool': 'Automated',
            'target': target,
            'scan_type': 'combined',
            'timestamp': all_results['timestamp'],
            'filepath': filepath
        })
        
    except Exception as e:
        message_queue.put(json.dumps({
            'type': 'error',
            'message': f'Scan error: {str(e)}'
        }))
    finally:
        message_queue.put('DONE')


@app.route('/scan/automated', methods=['POST'])
def automated_scan():
    """Start automated combined scan"""
    try:
        target = request.form.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Generate scan ID
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Create message queue for this scan
        message_queue = queue.Queue()
        active_scans[scan_id] = message_queue
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_automated_scan,
            args=(scan_id, target, message_queue)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/scan/automated/stream/<scan_id>')
def automated_scan_stream(scan_id):
    """Stream live updates for automated scan"""
    def generate():
        if scan_id not in active_scans:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Scan not found'})}\n\n"
            return
        
        message_queue = active_scans[scan_id]
        
        while True:
            try:
                message = message_queue.get(timeout=1)
                
                if message == 'DONE':
                    # Clean up
                    del active_scans[scan_id]
                    break
                
                yield f"data: {message}\n\n"
                
            except queue.Empty:
                # Send heartbeat to keep connection alive
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/ai-status')
def ai_status():
    """Check if AI analysis is available"""
    return jsonify({
        'enabled': gemini_analyzer.is_enabled(),
        'message': 'AI analysis is ready' if gemini_analyzer.is_enabled() else 'Configure GEMINI_API_KEY to enable AI analysis'
    })


@app.route('/api/analyze/nmap', methods=['POST'])
def analyze_nmap():
    """Get AI analysis for Nmap results"""
    try:
        data = request.get_json()
        results = data.get('results')
        
        if not results:
            return jsonify({'error': 'No results provided'}), 400
        
        analysis = gemini_analyzer.analyze_nmap_results(results)
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze/nikto', methods=['POST'])
def analyze_nikto():
    """Get AI analysis for Nikto results"""
    try:
        data = request.get_json()
        results = data.get('results')
        
        if not results:
            return jsonify({'error': 'No results provided'}), 400
        
        analysis = gemini_analyzer.analyze_nikto_results(results)
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze/sqlmap', methods=['POST'])
def analyze_sqlmap():
    """Get AI analysis for SQLMap results"""
    try:
        data = request.get_json()
        results = data.get('results')
        
        if not results:
            return jsonify({'error': 'No results provided'}), 400
        
        analysis = gemini_analyzer.analyze_sqlmap_results(results)
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze/combined', methods=['POST'])
def analyze_combined():
    """Get AI analysis for combined scan results"""
    try:
        data = request.get_json()
        results = data.get('results')
        
        if not results:
            return jsonify({'error': 'No results provided'}), 400
        
        analysis = gemini_analyzer.analyze_combined_results(results)
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("[*] Starting CyberAuditX Web Application")
    print("[*] Access the application at: http://127.0.0.1:5000")
    
    if gemini_analyzer.is_enabled():
        print("[+] AI Analysis: ENABLED (Google Gemini)")
    else:
        print("[!] AI Analysis: DISABLED (Set GEMINI_API_KEY environment variable to enable)")
    
    print("[*] Press CTRL+C to stop the server")
    app.run(debug=True, host='0.0.0.0', port=5000)
