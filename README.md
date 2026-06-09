git clone <repository-url> CyberAuditX
# CyberAuditX

Automated security testing with a modern web UI, sequential scans (Nmap → SQLMap → Nikto), live Server-Sent Events (SSE) updates, and AI-powered analysis using Google Gemini. Optimized for fast runs, clear summaries, and downloadable reports.

## Highlights
- 🚀 Automated workflow: Nmap discovery → SQLMap probing → Nikto web sweep
- 🤖 **NEW: AI-Powered Analysis** - Get intelligent summaries, risk assessments, and remediation recommendations using Google Gemini
- 🔴 Live vulnerability feed via SSE with severity badges
- ⚡ Speed-tuned defaults: Nmap quick profiles, SQLMap smart retries, Nikto capped ~3–8 minutes with `-maxtime`, `-timeout`, `-ask no`
- 🖥️ Modern UI: glassmorphism, gradients, responsive cards, recent-scan table
- 📑 Artifacts: JSON reports in `scan_results/`, view/download from the UI

## AI Analysis Features
CyberAuditX now integrates Google Gemini AI to provide:
- 📊 **Intelligent Summaries** - Natural language explanation of scan findings
- ⚠️ **Risk Assessment** - Automated risk scoring (0-100) with detailed justification
- 💡 **Smart Recommendations** - Actionable, prioritized security fixes
- 🗺️ **Security Roadmap** - Immediate, short-term, and long-term action plans
- 🎯 **Impact Analysis** - Understanding the real-world implications of vulnerabilities

### Setup AI Analysis
1. Get your Google Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Set the environment variable:
   ```bash
   export GEMINI_API_KEY='your-api-key-here'
   ```
3. Or edit `config.py` and set `GEMINI_API_KEY` (not recommended for production)
4. Install the AI package:
   ```bash
   pip install -r requirements.txt
   ```

When configured, you'll see a **🤖 AI Analysis** button on all scan result pages!

## Quick Start (web UI)
```bash
cd /home/pritesh/Desktop/CyberAuditX
.venv/bin/python web_app.py
# open http://localhost:5000
```

1) Go to 🤖 Automated, enter target (URL runs all three; IP runs Nmap+Nikto if web ports found).  
2) Watch live updates for each phase.  
3) View/download results when finished (stored in `scan_results/`).

## API (curl)
Start automated scan:
```bash
curl -X POST http://localhost:5000/scan/automated -F "target=http://example.com"
```
Stream live SSE:
```bash
curl http://localhost:5000/scan/automated/stream/{scan_id}
```

## Safe Test Targets
- http://testphp.vulnweb.com/
- http://testhtml5.vulnweb.com/
- http://scanme.nmap.org

## Tech Stack
- Flask 3 + SSE streaming
- Threading + queue for background scans
- **Google Gemini Pro AI** for intelligent vulnerability analysis
- Nmap 7.x, Nikto 2.x (optimized), SQLMap 1.x
- Vanilla JS + CSS animations (no frontend framework)

## Performance (approx)
- Nmap quick: 30–60s
- SQLMap basic: 1–3m
- Nikto optimized: 2–3m (capped to ~8m max)
- Total typical: 3–7m per target

## File Map
- **web_app.py** — Flask app, routes, SSE, orchestrator, AI API endpoints
- **ai_analyzer.py** — Google Gemini integration for intelligent analysis
- **config.py** — Configuration (API keys, feature flags)
- **templates/** — UI pages (automated, nmap, nikto, sqlmap, landing) with AI integration
- **scanner/** — nmap_scan.py, sqlmap_scan.py, nikto_scan.py (speed-tuned, severity summary)
- **scan_results/** — JSON reports

## Troubleshooting
- **Tools missing**: install nmap, nikto, sqlmap and restart the app.
- **SSE not streaming**: disable blocking extensions, try another browser.
- **Scan stuck**: target may be offline/firewalled; try a known test target.
- **AI Analysis not available**: 
  - Check that `GEMINI_API_KEY` environment variable is set
  - Verify API key is valid at [Google AI Studio](https://makersuite.google.com/app/apikey)
  - Restart web_app.py after setting the key
  - Check startup message shows "[+] AI Analysis: ENABLED (Google Gemini)"
- **AI Analysis fails**: 
  - Rate limit exceeded: wait a few seconds and try again
  - Invalid API key: regenerate key in Google AI Studio
  - Network issues: check internet connectivity

## Security & Legal
- Only scan assets you own or have explicit written permission to test.
- Scans generate network traffic; inform stakeholders before running.

## License & Disclaimer
Educational/authorized testing only. Use at your own risk; no warranty provided.

**Version**: 2.1.0 (AI-Enhanced)  
**Last Updated**: February 16, 2025
