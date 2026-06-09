# CyberAuditX Setup Guide

## Prerequisites
- Python 3.6 or higher
- Nmap 7.x
- Nikto 2.x
- SQLMap 1.x
- Google Gemini API key (for AI features)

## Installation Steps

### 1. Install System Dependencies

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install nmap nikto sqlmap python3 python3-pip
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install nmap nikto sqlmap python3 python3-pip
```

**macOS:**
```bash
brew install nmap nikto sqlmap python3
```

### 2. Install Python Dependencies
```bash
cd /home/pritesh/Desktop/CyberAuditX
pip install -r requirements.txt
```

This installs:
- Flask 3.0.0 (Web framework)
- Werkzeug 3.0.1 (WSGI utilities)
- google-generativeai 0.3.0 (AI analysis)

### 3. Configure Google Gemini AI (Required for AI Features)

#### Get Your API Key
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the generated key

#### Set Environment Variable (Recommended)
```bash
export GEMINI_API_KEY='your-api-key-here'
```

To make it permanent, add to your `~/.bashrc` or `~/.zshrc`:
```bash
echo "export GEMINI_API_KEY='your-api-key-here'" >> ~/.bashrc
source ~/.bashrc
```

#### Alternative: Configure in File (Not Recommended for Production)
Edit `config.py`:
```python
GEMINI_API_KEY = "your-api-key-here"  # Replace with your actual key
```

⚠️ **Warning**: Never commit API keys to version control!

### 4. Verify Installation
```bash
# Check Python version
python3 --version

# Check scanner tools
nmap --version
nikto -Version
sqlmap --version

# Check Python packages
pip list | grep -E "Flask|google-generativeai"
```

### 5. Start the Application
```bash
python3 web_app.py
```

You should see:
```
[+] Starting CyberAuditX Web Application...
[+] Checking scanner tools...
[+] Nmap: AVAILABLE
[+] Nikto: AVAILABLE  
[+] SQLMap: AVAILABLE
[+] AI Analysis: ENABLED (Google Gemini)  # If API key is configured
[+] Server starting on http://0.0.0.0:5000
```

### 6. Access the Web UI
Open your browser and navigate to:
```
http://localhost:5000
```

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

### AI Analysis Not Working

**Symptom**: Startup shows "[+] AI Analysis: DISABLED (API key not configured)"

**Solution**:
1. Verify API key is set: `echo $GEMINI_API_KEY`
2. If empty, set it: `export GEMINI_API_KEY='your-key'`
3. Restart web_app.py
4. Check startup message shows "ENABLED"

**Symptom**: "API key is invalid" error

**Solution**:
1. Regenerate key at [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Update environment variable or config.py
3. Restart application

**Symptom**: "Rate limit exceeded" error

**Solution**:
- Wait 60 seconds before requesting another analysis
- Google Gemini free tier has usage limits
- Consider upgrading to paid tier for higher limits

### Scanner Tools Not Found

**Symptom**: Startup shows "Nmap: NOT FOUND"

**Solution**:
```bash
# Install missing tool
sudo apt install nmap  # or nikto, sqlmap
```

### SSE Streaming Issues

**Symptom**: Live scan updates not showing in automated scans

**Solution**:
1. Disable browser extensions blocking SSE
2. Try different browser (Chrome, Firefox recommended)
3. Check browser console for JavaScript errors (F12)

### Port Already in Use

**Symptom**: "Address already in use" error on startup

**Solution**:
```bash
# Find process using port 5000
lsof -i :5000
# Kill the process
kill -9 <PID>
# Or change port in web_app.py:
# app.run(host='0.0.0.0', port=8080)
```

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
- Add more flags in `scan()` method

**Nikto** (`scanner/nikto_scan.py`):
- Current: `nikto -h <target> -Tuning 123bde -maxtime 120s -ask no`
- Modify command in `scan()` method

**SQLMap** (`scanner/sqlmap_scan.py`):
- Default uses `basic_scan` method
- Add custom options in method parameters

## Production Deployment

### Security Recommendations
1. **Never expose directly to internet** - Use reverse proxy (nginx/Apache)
2. **Enable HTTPS** - Use SSL certificates
3. **Add authentication** - Implement user login system
4. **Rate limiting** - Prevent abuse
5. **Input validation** - Already implemented, but review for your use case
6. **Secure API keys** - Use environment variables, never commit to git
7. **Firewall rules** - Restrict access to authorized IPs

### Performance Tuning
- Use `gunicorn` or `uwsgi` instead of Flask development server
- Set `debug=False` in production
- Configure proper logging
- Monitor resource usage during scans

### Example with Gunicorn
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 web_app:app
```

## Getting Help

If you encounter issues:
1. Check the Troubleshooting section above
2. Review application logs in terminal
3. Verify all prerequisites are installed
4. Test with safe public targets first
5. Check browser console (F12) for JavaScript errors

## Version Information
- **Current Version**: 2.1.0 (AI-Enhanced)
- **Last Updated**: February 16, 2025
- **Python**: 3.6+
- **Flask**: 3.0.0
- **Google Gemini**: Pro model via generativeai 0.3.0
