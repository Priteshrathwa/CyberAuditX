# CyberAuditX Setup Guide

Complete installation and configuration guide for CyberAuditX security scanner with AI-powered vulnerability analysis.

## Table of Contents
1. [Quick Start (5 minutes)](#quick-start)
2. [Full Installation](#installation-steps)
3. [Configuration](#configuration)
4. [Verification](#verification)
5. [Troubleshooting](#troubleshooting)
6. [Production Deployment](#production-deployment)

---

## Quick Start

Get CyberAuditX running in 5 minutes:

```bash
# Clone and setup
git clone https://github.com/Priteshrathwa/CyberAuditX.git
cd CyberAuditX

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install everything
pip install -r requirements.txt

# On Ubuntu/Debian, install system dependencies
sudo apt install nmap nikto sqlmap libxml-writer-perl

# Set Google Gemini API key (optional for AI features)
export GEMINI_API_KEY='your-api-key-here'

# Start server
python3 web_app.py

# Open browser to http://localhost:5000
```

---

## Prerequisites
- Python 3.6 or higher
- Nmap 7.x
- Nikto 2.x (requires Perl XML::Writer module)
- SQLMap 1.x
- Google Gemini API key (optional, for AI features)
- 2GB RAM minimum
- Linux/macOS/Windows with WSL2

## Installation Steps

### 1. Install System Dependencies

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    nmap nikto sqlmap \
    perl libxml-writer-perl libxml2-dev \
    git curl

# Verify Perl module installation
perl -e 'use XML::Writer; print "OK\n"'
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install -y \
    python3 python3-pip \
    nmap nikto sqlmap \
    perl perl-XML-Writer \
    git curl
```

**macOS:**
```bash
brew install nmap nikto sqlmap python3
brew install perl
cpan XML::Writer
```

**Windows (with WSL2):**
```bash
# Inside WSL2 terminal
sudo apt update && sudo apt install -y nmap nikto sqlmap python3 python3-pip perl libxml-writer-perl
```

### 2. Setup Python Virtual Environment

It's best practice to use a virtual environment to isolate dependencies:

```bash
# Navigate to project directory
cd /path/to/CyberAuditX

# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate           # Linux/macOS
# OR
.venv\Scripts\activate              # Windows PowerShell
# OR
.venv\Scripts\activate.bat          # Windows CMD

# You should see (.venv) in your prompt
```

### 3. Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs:
- Flask 3.0.0 (Web framework)
- Werkzeug 3.0.1 (WSGI utilities)
- google-generativeai 0.3.0 (AI analysis)
- SQLMap and other dependencies

### 4. Configure Google Gemini AI (Optional - for AI Features)

#### Get Your API Key
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the generated key

#### Set Environment Variable (Recommended)
```bash
# For current session only
export GEMINI_API_KEY='your-api-key-here'

# For permanent setup, add to ~/.bashrc or ~/.zshrc
echo "export GEMINI_API_KEY='your-api-key-here'" >> ~/.bashrc
source ~/.bashrc

# Verify it's set
echo $GEMINI_API_KEY
```

#### For Windows (PowerShell):
```powershell
$env:GEMINI_API_KEY='your-api-key-here'

# Permanent setup (Windows):
[Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "your-api-key-here", "User")
```

#### Alternative: Configure in File (Not Recommended for Production)
Edit `config.py`:
```python
GEMINI_API_KEY = "your-api-key-here"  # Replace with your actual key
```

⚠️ **Warning**: Never commit API keys to version control! Use environment variables only.

---

## Verification

### 5. Verify Installation

Test all components are properly installed:

```bash
# Activate virtual environment first
source .venv/bin/activate

# Check Python version (should be 3.6+)
python3 --version

# Check system tools
nmap --version
nikto -Version
sqlmap --version

# Check Perl XML module
perl -e 'use XML::Writer; print "✓ XML::Writer installed\n"'

# Check Python packages
pip list | grep -E "Flask|google-generativeai|sqlmap"
```

Expected output for Flask:
```
Flask                    3.0.0
Werkzeug                 3.0.1
google-generativeai      0.3.0
sqlmap                   1.x.x
```

### 6. Start the Application

```bash
# Activate virtual environment (if not already)
source .venv/bin/activate

# Start the web application
python3 web_app.py
```

Expected startup output:
```
[+] Starting CyberAuditX Web Application...
[+] Checking scanner tools...
[+] Nmap: ✓ AVAILABLE
[+] Nikto: ✓ AVAILABLE
[+] SQLMap: ✓ AVAILABLE
[+] AI Analysis: ✓ ENABLED (Google Gemini)    # If API key is set
[+] Server starting on http://0.0.0.0:5000
 * WARNING in production, set debug=False
 * Serving Flask app 'web_app'
 * Running on http://0.0.0.0:5000
```

If you see `AI Analysis: DISABLED`, the API key is not set (this is OK, AI features just won't work).

### 7. Access the Web UI
Open your browser and navigate to:
```
http://localhost:5000
```

---

## Configuration

## Usage Guide

### Individual Scans

#### Nmap Scan
- Navigate to "Nmap Scanner"
- Enter target: `scanme.nmap.org` or `192.168.1.1`
- Click "Start Scan"
- After completion, click "🤖 AI Analysis" for intelligent insights

#### Nikto Scan
- Navigate to "Nikto Scanner"
- Enter target URL: `http://testphp.vulnweb.com`
- Click "Start Scan"
- Review findings by severity (High, Medium, Low, Info)
- Click "🤖 AI Analysis" for risk assessment

#### SQLMap Scan
- Navigate to "SQLMap Scanner"
- Enter target URL: `http://testphp.vulnweb.com/artists.php?artist=1`
- Click "Start Scan"
- Review injection points and database information
- Click "🤖 AI Analysis" for exploitation scenarios and fixes

### Automated Workflow
- Navigate to "🤖 Automated Scan"
- Enter target URL: `http://testphp.vulnweb.com`
- Click "Start Automated Scan"
- Watch live progress:
  1. **Nmap Discovery** - Identifies open ports and services
  2. **SQLMap Probing** - Tests for SQL injection vulnerabilities
  3. **Nikto Sweep** - Comprehensive web vulnerability scan
- After completion, click "🤖 AI Analysis" for comprehensive security assessment

### AI Analysis Features

Each scan type provides specialized AI insights:

**Nmap Analysis:**
- Summary of discovered services
- Security risks for each open port
- Prioritized recommendations

**Nikto Analysis:**
- Overall risk level assessment
- Critical issues requiring immediate attention
- Detailed fix suggestions

**SQLMap Analysis:**
- Impact assessment of SQL injection vulnerabilities
- Exploitation scenarios
- Immediate fixes and long-term improvements

**Combined Automated Analysis:**
- Executive summary
- Risk score (0-100)
- Critical actions prioritized
- Compliance concerns (OWASP, PCI-DSS, GDPR)
- Security roadmap (Immediate/Short-term/Long-term)

## Safe Testing Targets

Always test on authorized targets only. Use these public testing sites:

- **http://testphp.vulnweb.com/** - ACUART vulnerable PHP application
- **http://testhtml5.vulnweb.com/** - HTML5 test site
- **http://scanme.nmap.org** - Nmap testing server

⚠️ **Legal Warning**: Only scan systems you own or have explicit written permission to test.

## Troubleshooting

### Nikto: XML::Writer Module Error

**Error:**
```
ERROR: Required module not found: XML::Writer
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install libxml-writer-perl

# Or via CPAN
perl -MCPAN -e 'install XML::Writer'

# Verify installation
perl -e 'use XML::Writer; print "✓ Installed\n"'
```

### Nikto: Not Executing

**Symptom**: Nikto scan doesn't run or times out

**Solution**:
1. Verify Nikto installed: `nikto -Version`
2. If not installed: `sudo apt install nikto`
3. Check Perl modules: `perl -e 'use XML::Writer; print "OK\n"'`
4. Try running nikto manually: `nikto -h scanme.nmap.org`

### AI Analysis Not Working

**Symptom**: Startup shows "[+] AI Analysis: DISABLED (API key not configured)"

**Solution**:
1. Verify API key is set: `echo $GEMINI_API_KEY`
2. If empty, set it:
   ```bash
   export GEMINI_API_KEY='your-key-here'
   python3 web_app.py
   ```
3. Check startup message shows "ENABLED"

**Symptom**: "API key is invalid" error

**Solution**:
1. Regenerate key at [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Update environment variable: `export GEMINI_API_KEY='new-key'`
3. Restart application

**Symptom**: "Rate limit exceeded" error

**Solution**:
- Google Gemini free tier limits requests per minute
- Wait 60 seconds before requesting another analysis
- Consider upgrading to paid tier for higher limits

### Scanner Tools Not Found

**Symptom**: 
```
[-] Nmap: NOT FOUND
```

**Solution**:
```bash
# Install missing tools
sudo apt install nmap nikto sqlmap

# Or on macOS
brew install nmap nikto sqlmap

# Verify installation
which nmap
which nikto
which sqlmap
```

### Python Module Not Found

**Symptom**:
```
ModuleNotFoundError: No module named 'flask'
```

**Solution**:
1. Activate virtual environment: `source .venv/bin/activate`
2. Reinstall dependencies: `pip install -r requirements.txt`
3. Verify: `pip list | grep Flask`

### Port Already in Use

**Symptom**: 
```
Address already in use: 0.0.0.0:5000
```

**Solution**:
```bash
# Find process using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or change port in web_app.py:
# Find this line at the end:
# app.run(host='0.0.0.0', port=5000, debug=False)
# Change to:
# app.run(host='0.0.0.0', port=8080, debug=False)

# On Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### SSE Streaming Issues

**Symptom**: Live scan updates not showing in automated scans

**Solution**:
1. Disable browser extensions (especially ad blockers)
2. Try different browser (Chrome, Firefox recommended)
3. Check browser console for errors (F12 → Console)
4. Clear browser cache and refresh

### Connection Refused

**Symptom**:
```
Connection refused: Could not connect to localhost:5000
```

**Solution**:
1. Check app is running: `ps aux | grep web_app.py`
2. Check terminal for startup errors
3. Verify port isn't blocked: `lsof -i :5000`
4. Try: `python3 web_app.py` from project directory

---

## Project Structure

```
CyberAuditX/
├── web_app.py              # Main Flask application
├── config.py               # Configuration (API keys, settings)
├── ai_analyzer.py          # Google Gemini AI integration
├── requirements.txt        # Python dependencies
├── scanner/
│   ├── nmap_scan.py       # Nmap scanner module
│   ├── nikto_scan.py      # Nikto scanner module (Perl-based)
│   └── sqlmap_scan.py     # SQLMap scanner module
├── templates/
│   ├── base.html          # Base template (navigation)
│   ├── index.html         # Home page
│   ├── nmap.html          # Nmap UI + AI results
│   ├── nikto.html         # Nikto UI + AI results
│   ├── sqlmap.html        # SQLMap UI + AI results
│   └── automated.html     # Combined automated scan UI
├── scan_results/          # JSON scan output storage
├── static/                # CSS/JS files (if added)
├── SETUP.md              # This file
├── README.md             # Project documentation
└── .venv/                # Virtual environment (local)
```

---

## Production Deployment

### Security Checklist

⚠️ **DO NOT expose directly to the internet without these steps:**

- [ ] Set `debug=False` in web_app.py
- [ ] Use HTTPS with valid SSL certificate
- [ ] Add authentication layer (reverse proxy, firewall rules)
- [ ] Store API keys in secure environment variable service
- [ ] Enable rate limiting on scan endpoints
- [ ] Restrict scanner access by IP whitelist
- [ ] Use `gunicorn` or `uwsgi` instead of Flask dev server
- [ ] Configure proper logging and monitoring
- [ ] Set resource limits (CPU, memory, timeout)
- [ ] Regular security updates: `pip install --upgrade -r requirements.txt`

### Using Gunicorn (Production Server)

```bash
# Install gunicorn
pip install gunicorn

# Run with multiple workers
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 300 web_app:app

# Or with systemd service (Linux)
sudo tee /etc/systemd/system/cyberauditx.service > /dev/null <<EOF
[Unit]
Description=CyberAuditX Security Scanner
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/opt/cyberauditx
Environment="GEMINI_API_KEY=your-key-here"
ExecStart=/opt/cyberauditx/.venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 web_app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start cyberauditx
sudo systemctl enable cyberauditx
```

### Nginx Reverse Proxy Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name cyberauditx.example.com;

    ssl_certificate /etc/ssl/certs/cyberauditx.crt;
    ssl_certificate_key /etc/ssl/private/cyberauditx.key;

    # Restrict access
    allow 192.168.1.0/24;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # For SSE streaming
        proxy_buffering off;
        proxy_cache off;
    }
}
```

---

## Usage Guide

### Testing Targets

Always use authorized targets. Recommended safe options:

- **http://testphp.vulnweb.com/** - ACUART vulnerable application
- **http://scanme.nmap.org** - Official Nmap test server
- **Local applications** - DVWA, Juice Shop, WebGoat (run locally)

### Individual Scans

**Nmap Scan:**
1. Navigate to "Nmap Scanner"
2. Enter: `scanme.nmap.org` or IP address
3. Click "Start Scan"
4. Results show PORT, STATE, SERVICE, VERSION
5. Click "🤖 AI Analysis" for insights

**Nikto Scan:**
1. Navigate to "Nikto Scanner"
2. Enter: `http://testphp.vulnweb.com`
3. Click "Start Scan"
4. Results grouped by CRITICAL/HIGH/MEDIUM/LOW/INFO
5. Click "🤖 AI Analysis" for recommendations

**SQLMap Scan:**
1. Navigate to "SQLMap Scanner"
2. Enter: `http://testphp.vulnweb.com/artists.php?artist=1`
3. Click "Start Scan"
4. Results show injection points and database info
5. Click "🤖 AI Analysis" for exploitation details

### Automated Workflow

1. Navigate to "🤖 Automated Scan"
2. Enter target URL
3. Click "Start Automated Scan"
4. Watch live progress (Nmap → SQLMap → Nikto)
5. After completion, click "🤖 AI Analysis"
6. Results include risk score, critical actions, compliance concerns

---

## Getting Help

If you encounter issues:

1. Check the Troubleshooting section above
2. Review terminal output for error messages
3. Verify prerequisites: `./verify-installation.sh` (if available)
4. Test with public targets first (scanme.nmap.org)
5. Check browser console (F12) for JavaScript errors
6. Review GitHub Issues: https://github.com/Priteshrathwa/CyberAuditX/issues

### Debug Mode

Enable verbose output:
```bash
# In web_app.py, set:
app.run(debug=True)

# Or set environment variable:
export FLASK_ENV=development
export FLASK_DEBUG=1
python3 web_app.py
```

---

## Version Information

- **Current Version**: 2.2.0 (AI-Enhanced)
- **Last Updated**: June 9, 2026
- **Python**: 3.6+ required
- **Flask**: 3.0.0+
- **Google Gemini**: Pro model via generativeai 0.3.0+
- **License**: MIT (as per repository)

---

## Advanced Configuration

### Change Default Port
Edit `web_app.py`, find the last line:
```python
app.run(host='0.0.0.0', port=5000, debug=False)
```
Change `port=5000` to your desired port.

### Disable AI Analysis
If you don't want AI features:
1. Set in `config.py`: `ENABLE_AI_ANALYSIS = False`
2. Or don't set `GEMINI_API_KEY` environment variable

### Customize Scan Commands

**Nmap** (`scanner/nmap_scan.py`):
- Current: `nmap -sV <target>`
- Modify scan() method to add additional flags

**Nikto** (`scanner/nikto_scan.py`):
- Current: `nikto -h <target> -Tuning 123bde -maxtime 120s -ask no`
- Edit _run_nikto_command() to customize

**SQLMap** (`scanner/sqlmap_scan.py`):
- Default uses `basic_scan` method
- Edit scan() method for custom options

---

**For more information, visit: https://github.com/Priteshrathwa/CyberAuditX**
