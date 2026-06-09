#!/usr/bin/env python3
"""
Configuration file for CyberAuditX
Store your API keys and settings here
"""

import os

# Google Gemini API Key
# Get your API key from: https://makersuite.google.com/app/apikey
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'AIzaSyBV2KvGeOTeFljD3VGhqnds-8Otx9YEVxk')

# If you prefer to hardcode (NOT recommended for production):
# GEMINI_API_KEY = 'your-api-key-here'

# Enable/Disable AI Analysis
ENABLE_AI_ANALYSIS = True if GEMINI_API_KEY else False
