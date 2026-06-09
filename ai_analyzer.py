#!/usr/bin/env python3
"""
AI Analysis Module using Google Gemini
Provides intelligent analysis and recommendations for security scan results
"""

import google.generativeai as genai
import json
import re
from config import GEMINI_API_KEY, ENABLE_AI_ANALYSIS


class GeminiAnalyzer:
    """AI-powered security scan analyzer using Google Gemini"""
    
    def __init__(self, api_key=None):
        """
        Initialize Gemini analyzer
        
        Args:
            api_key (str): Google Gemini API key
        """
        self.api_key = api_key or GEMINI_API_KEY
        self.enabled = bool(self.api_key) and ENABLE_AI_ANALYSIS
        
        if self.enabled:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('models/gemini-2.5-flash')
    
    @staticmethod
    def extract_json(text):
        """
        Extract JSON from response text, handling markdown code blocks
        
        Args:
            text (str): Response text that may contain JSON
            
        Returns:
            dict: Parsed JSON object or empty dict if extraction fails
        """
        try:
            # Try direct JSON parsing first
            return json.loads(text)
        except:
            pass
        
        # Try to extract JSON from markdown code blocks
        patterns = [
            r'```json\s*(.*?)```',  # ```json ... ```
            r'```\s*(.*?)```',       # ``` ... ```
            r'\{.*\}',               # Raw JSON object
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            if matches:
                for match in matches:
                    try:
                        return json.loads(match.strip())
                    except:
                        continue
        
        # If all parsing fails, return empty dict
        return {}
    
    def is_enabled(self):
        """Check if AI analysis is enabled"""
        return self.enabled
    
    def analyze_nmap_results(self, results):
        """
        Analyze Nmap scan results
        
        Args:
            results (dict): Nmap scan results
            
        Returns:
            dict: AI analysis with summary, risks, and recommendations
        """
        if not self.enabled:
            return {'error': 'AI analysis is not enabled. Please configure GEMINI_API_KEY.'}
        
        try:
            # Prepare data for analysis
            ports = results.get('ports', [])
            open_ports = [p for p in ports if p.get('state') == 'open']
            
            prompt = f"""You are a cybersecurity expert analyzing network scan results.

Target: {results.get('target')}
Total Ports Scanned: {results.get('summary', {}).get('total_ports', 0)}
Open Ports: {results.get('summary', {}).get('open_ports', 0)}

Open Ports Details:
{json.dumps(open_ports, indent=2)}

Please provide:
1. A brief summary (2-3 sentences) of the scan findings
2. Security risks identified (list 3-5 key risks)
3. Specific recommendations to mitigate these risks (actionable steps)

Format your response as JSON with keys: "summary", "risks" (array), "recommendations" (array)
"""
            
            response = self.model.generate_content(prompt)
            
            # Parse JSON response - extract from markdown if needed
            analysis = self.extract_json(response.text)
            
            if not analysis:
                analysis = {
                    'summary': response.text[:500],
                    'risks': [],
                    'recommendations': []
                }
            
            return analysis
            
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def analyze_nikto_results(self, results):
        """
        Analyze Nikto scan results
        
        Args:
            results (dict): Nikto scan results
            
        Returns:
            dict: AI analysis with summary, critical issues, and fixes
        """
        if not self.enabled:
            return {'error': 'AI analysis is not enabled. Please configure GEMINI_API_KEY.'}
        
        try:
            findings = results.get('findings', [])
            summary = results.get('summary', {})
            by_severity = summary.get('by_severity', {})
            
            # Get critical and high severity findings
            critical_high = [f for f in findings if f.get('severity') in ['critical', 'high']]
            
            prompt = f"""You are a web security expert analyzing Nikto vulnerability scan results.

Target: {results.get('target')}
Total Findings: {summary.get('total_findings', 0)}
Critical: {by_severity.get('critical', 0)}
High: {by_severity.get('high', 0)}
Medium: {by_severity.get('medium', 0)}
Low: {by_severity.get('low', 0)}

Critical & High Severity Issues:
{json.dumps(critical_high[:10], indent=2)}

Please provide:
1. Executive summary (2-3 sentences) of the web application's security posture
2. Top 5 critical issues that need immediate attention
3. Detailed remediation steps for each critical issue

Format your response as JSON with keys: "summary", "critical_issues" (array of objects with "issue" and "fix"), "overall_risk_level" (Low/Medium/High/Critical)
"""
            
            response = self.model.generate_content(prompt)
            
            # Parse JSON response - extract from markdown if needed
            analysis = self.extract_json(response.text)
            
            if not analysis:
                analysis = {
                    'summary': response.text[:500],
                    'critical_issues': [],
                    'overall_risk_level': 'Unknown'
                }
            return analysis
        
            
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def analyze_sqlmap_results(self, results):
        """
        Analyze SQLMap scan results
        
        Args:
            results (dict): SQLMap scan results
            
        Returns:
            dict: AI analysis with impact assessment and remediation
        """
        if not self.enabled:
            return {'error': 'AI analysis is not enabled. Please configure GEMINI_API_KEY.'}
        
        try:
            vulnerabilities = results.get('vulnerabilities', [])
            summary = results.get('summary', {})
            
            prompt = f"""You are a database security expert analyzing SQL injection test results.

Target: {results.get('target')}
Vulnerabilities Found: {summary.get('total_vulnerabilities', 0)}
Vulnerable Parameters: {summary.get('vulnerable_parameters', 0)}

Vulnerabilities:
{json.dumps(vulnerabilities, indent=2)}

Please provide:
1. Impact assessment (2-3 sentences) - explain the severity and potential damage
2. Exploitation scenarios - what an attacker could do
3. Immediate remediation steps (prioritized list)
4. Long-term security improvements

Format your response as JSON with keys: "impact_assessment", "exploitation_scenarios" (array), "immediate_fixes" (array), "long_term_improvements" (array)
"""
            
            response = self.model.generate_content(prompt)
            
            # Parse JSON response - extract from markdown if needed
            analysis = self.extract_json(response.text)
            
            if not analysis:
                analysis = {
                    'impact_assessment': response.text[:500],
                    'exploitation_scenarios': [],
                    'immediate_fixes': [],
                    'long_term_improvements': []
                }
            return analysis
            
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def analyze_combined_results(self, combined_results):
        """
        Analyze combined automated scan results
        
        Args:
            combined_results (dict): Combined scan results from all tools
            
        Returns:
            dict: Comprehensive AI analysis
        """
        if not self.enabled:
            return {'error': 'AI analysis is not enabled. Please configure GEMINI_API_KEY.'}
        
        try:
            nmap = combined_results.get('nmap', {})
            sqlmap = combined_results.get('sqlmap', {})
            nikto = combined_results.get('nikto', {})
            vulnerabilities = combined_results.get('vulnerabilities', [])
            
            prompt = f"""You are a chief security officer analyzing comprehensive security scan results for a target system.

Target: {combined_results.get('target')}
Scan Timestamp: {combined_results.get('timestamp')}

Nmap Results:
- Open Ports: {nmap.get('summary', {}).get('open_ports', 0) if nmap else 0}

SQLMap Results:
- SQL Vulnerabilities: {sqlmap.get('summary', {}).get('total_vulnerabilities', 0) if sqlmap else 0}

Nikto Results:
- Web Vulnerabilities: {nikto.get('summary', {}).get('total_findings', 0) if nikto else 0}

Total Issues Found: {len(vulnerabilities)}

Please provide:
1. Executive Summary (3-4 sentences) - overall security posture
2. Risk Score (0-100) with justification
3. Top 5 Critical Actions (prioritized by impact)
4. Compliance Concerns (if any)
5. Suggested Security Roadmap (3 phases: Immediate, Short-term, Long-term)

Format your response as JSON with keys: "executive_summary", "risk_score", "risk_justification", "critical_actions" (array), "compliance_concerns" (array), "roadmap" (object with "immediate", "short_term", "long_term" arrays)
"""
            
            response = self.model.generate_content(prompt)
            
            # Parse JSON response - extract from markdown if needed
            analysis = self.extract_json(response.text)
            
            if not analysis:
                analysis = {
                    'executive_summary': response.text[:500],
                    'risk_score': 50,
                    'risk_justification': 'Unable to parse analysis',
                    'critical_actions': [],
                    'compliance_concerns': [],
                    'roadmap': {
                        'immediate': [],
                        'short_term': [],
                        'long_term': []
                    }
                }
            
            return analysis
            
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}


# Global instance
gemini_analyzer = GeminiAnalyzer()
