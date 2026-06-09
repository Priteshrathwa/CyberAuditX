# Quick Reference - AI Integration

## Essential Commands

### Start Application
```bash
cd /home/pritesh/Desktop/CyberAuditX
export GEMINI_API_KEY='your-api-key-here'
python3 web_app.py
```

### Get Gemini API Key
Visit: https://makersuite.google.com/app/apikey

### Install Dependencies
```bash
pip install -r requirements.txt
# Installs: Flask, Werkzeug, google-generativeai
```

### Check AI Status
Look for this in startup output:
```
[+] AI Analysis: ENABLED (Google Gemini)  ✅ Good!
[+] AI Analysis: DISABLED (API key not configured)  ❌ Need to set key
```

## AI Features Quick Guide

### Individual Scan Analysis
1. Run any scan (Nmap/Nikto/SQLMap)
2. Wait for completion
3. Click **🤖 AI Analysis** button
4. View intelligent insights

### Automated Scan Analysis
1. Run automated scan workflow
2. All three scans complete automatically
3. Click **🤖 AI Analysis** for combined results
4. Get comprehensive security assessment

## What AI Provides

### Nmap Analysis
- 📊 Service summary
- ⚠️ Security risks per port
- 💡 Recommendations

### Nikto Analysis
- 🔴 Overall risk level
- ⚡ Critical issues
- 🛠️ Fix suggestions

### SQLMap Analysis
- 💥 Impact assessment
- 🎯 Exploitation scenarios
- 🔧 Immediate fixes
- 📈 Long-term improvements

### Combined Analysis
- 📋 Executive summary
- 🎚️ Risk score (0-100)
- ⚡ Critical actions
- 📜 Compliance concerns
- 🗺️ Security roadmap

## Troubleshooting One-Liners

```bash
# Check if API key is set
echo $GEMINI_API_KEY

# Set API key (replace with yours)
export GEMINI_API_KEY='AIzaSyD...'

# Make it permanent (bash)
echo "export GEMINI_API_KEY='AIzaSyD...'" >> ~/.bashrc && source ~/.bashrc

# Make it permanent (zsh)
echo "export GEMINI_API_KEY='AIzaSyD...'" >> ~/.zshrc && source ~/.zshrc

# Install AI package
pip install google-generativeai==0.3.0

# Check installation
pip show google-generativeai

# Restart application
pkill -f web_app.py && python3 web_app.py
```

## API Endpoints

```bash
# Check AI availability
curl http://localhost:5000/api/ai-status

# Analyze Nmap results (requires scan_id)
curl -X POST http://localhost:5000/api/analyze/nmap \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "nmap_quick_20250216_123456"}'

# Analyze Nikto results
curl -X POST http://localhost:5000/api/analyze/nikto \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "nikto_basic_20250216_123456"}'

# Analyze SQLMap results
curl -X POST http://localhost:5000/api/analyze/sqlmap \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "sqlmap_basic_20250216_123456"}'

# Analyze combined automated scan
curl -X POST http://localhost:5000/api/analyze/combined \
  -H "Content-Type: application/json" \
  -d '{"nmap_results": {...}, "sqlmap_results": {...}, "nikto_results": {...}}'
```

## File Locations

- **AI Module**: `ai_analyzer.py`
- **Configuration**: `config.py`
- **Web App**: `web_app.py`
- **Scan Results**: `scan_results/`
- **UI Templates**: `templates/*.html`

## Common Issues

| Issue | Solution |
|-------|----------|
| AI button missing | Check `GEMINI_API_KEY` is set |
| "API key invalid" error | Regenerate key at AI Studio |
| "Rate limit exceeded" | Wait 60 seconds, try again |
| No AI analysis shown | Check browser console (F12) |
| Startup shows "DISABLED" | Run `export GEMINI_API_KEY='...'` |

## Testing

Safe targets for testing:
- http://testphp.vulnweb.com
- http://scanme.nmap.org

**Never scan unauthorized targets!**

## Pro Tips

1. **Set API key system-wide**: Add to `.bashrc`/`.zshrc` for automatic loading
2. **Monitor rate limits**: Free tier has usage caps, space out analysis requests
3. **Save important analysis**: Copy text before closing results
4. **Use combined analysis**: More comprehensive than individual scans
5. **Check startup message**: Confirms AI is enabled before running scans

## Need Help?

1. Read SETUP.md for detailed instructions
2. Check terminal logs for error messages
3. Verify API key at https://makersuite.google.com/app/apikey
4. Test with safe public targets first
5. Check browser console for JavaScript errors (F12)
