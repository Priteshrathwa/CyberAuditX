#!/usr/bin/env python3
"""
Configuration file for CyberAuditX
Store your API keys and settings here
"""

import os

# Google Gemini API Key
# Get your API key from: https://makersuite.google.com/app/apikey
# IMPORTANT: Use environment variable only, never hardcode!
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', None)

# How to set it:
# export GEMINI_API_KEY='your-actual-key-here'
# Then run: python3 web_app.py

# Enable/Disable AI Analysis
ENABLE_AI_ANALYSIS = True if GEMINI_API_KEY else False
