"""
Technology Stack Detector - ENTERPRISE GRADE
Detects web server, language, framework, OS automatically
FIXED: Enhanced detection patterns for ANY tech stack
"""

import logging
import re
from typing import Dict

logger = logging.getLogger(__name__)


class TechnologyDetector:
    """
    ENTERPRISE Technology Stack Detector
    Works for ANY web application stack
    """
    
    def __init__(self):
        # Signature patterns (COMPREHENSIVE)
        self.web_server_patterns = {
            'apache': [r'apache', r'httpd', r'/etc/apache', r'.htaccess', r'mod_'],
            'nginx': [r'nginx', r'/etc/nginx', r'nginx.conf'],
            'iis': [r'iis', r'microsoft-iis', r'web.config', r'aspnet'],
            'tomcat': [r'tomcat', r'catalina', r'webapps'],
            'nodejs': [r'node', r'express', r'koa', r'npm'],
            'lighttpd': [r'lighttpd'],
            'caddy': [r'caddy'],
            'gunicorn': [r'gunicorn', r'wsgi'],
            'uvicorn': [r'uvicorn', r'asgi']
        }
        
        self.language_patterns = {
            'php': [r'\.php', r'php:', r'/var/www/html', r'composer', r'laravel', r'symfony'],
            'python': [r'\.py', r'wsgi', r'django', r'flask', r'python', r'pip', r'virtualenv'],
            'javascript': [r'\.js', r'node', r'express', r'react', r'vue', r'angular', r'npm'],
            'java': [r'\.java', r'\.jsp', r'servlet', r'spring', r'struts', r'maven'],
            'ruby': [r'\.rb', r'rails', r'rack', r'sinatra', r'gem'],
            'go': [r'\.go', r'golang'],
            'dotnet': [r'\.aspx', r'\.cshtml', r'asp\.net', r'c#', r'razor'],
            'perl': [r'\.pl', r'\.cgi', r'perl'],
            'rust': [r'\.rs', r'cargo', r'rust']
        }
        
        self.framework_patterns = {
            'django': [r'django', r'wsgi'],
            'flask': [r'flask'],
            'express': [r'express', r'expressjs'],
            'spring': [r'spring', r'springboot'],
            'laravel': [r'laravel'],
            'symfony': [r'symfony'],
            'rails': [r'rails', r'ruby on rails'],
            'asp.net': [r'asp\.net', r'aspx'],
            'react': [r'react', r'reactjs'],
            'angular': [r'angular'],
            'vue': [r'vue', r'vuejs']
        }
        
        self.os_patterns = {
            'linux': [r'/var/', r'/etc/', r'/usr/', r'ubuntu', r'debian', r'centos', r'rhel'],
            'windows': [r'c:\\', r'windows', r'iis', r'\\\\'],
            'unix': [r'/usr/', r'/opt/', r'bsd']
        }
        
        logger.info("✅ Technology Detector initialized")
        logger.info(f"   📊 {len(self.web_server_patterns)} web server patterns")
        logger.info(f"   📊 {len(self.language_patterns)} language patterns")
    
    def detect_from_incident(self, incident: Dict) -> Dict:
        """Detect technology stack from incident data (UNIVERSAL)"""
        tech_stack = {
            'web_server': 'unknown',
            'language': 'unknown',
            'framework': 'unknown',
            'os': 'unknown',
            'confidence': 0.0
        }
        
        # Collect all text data from incident
        text_data = self._extract_text_data(incident)
        
        # Detect each component
        tech_stack['web_server'] = self._detect_web_server(text_data)
        tech_stack['language'] = self._detect_language(text_data)
        tech_stack['framework'] = self._detect_framework(text_data)
        tech_stack['os'] = self._detect_os(text_data)
        
        # Calculate confidence
        detected = sum(1 for v in tech_stack.values() if v != 'unknown')
        tech_stack['confidence'] = detected / 4.0
        
        logger.info(f"   Detected: {tech_stack['web_server']}/{tech_stack['language']}/{tech_stack['framework']} ({tech_stack['confidence']*100:.0f}% confidence)")
        
        return tech_stack
    
    def _extract_text_data(self, incident: Dict) -> str:
        """Extract all text from incident for analysis (UNIVERSAL)"""
        text_parts = []
        
        # Get data from all alerts
        for alert in incident.get('alerts', []):
            url = alert.get('url', '')
            text_parts.append(url)
            
            vulnerability = alert.get('vulnerability', '')
            text_parts.append(vulnerability)
            
            description = alert.get('description', '')
            text_parts.append(description)
            
            evidence = alert.get('evidence', '')
            text_parts.append(evidence)
            
            solution = alert.get('solution', '')
            text_parts.append(solution)
        
        return ' '.join(text_parts).lower()
    
    def _detect_web_server(self, text: str) -> str:
        """Detect web server (UNIVERSAL)"""
        scores = {}
        
        for server, patterns in self.web_server_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, text, re.IGNORECASE))
            if score > 0:
                scores[server] = score
        
        if scores:
            return max(scores, key=scores.get)
        return 'unknown'
    
    def _detect_language(self, text: str) -> str:
        """Detect programming language (UNIVERSAL)"""
        scores = {}
        
        for lang, patterns in self.language_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, text, re.IGNORECASE))
            if score > 0:
                scores[lang] = score
        
        if scores:
            return max(scores, key=scores.get)
        return 'unknown'
    
    def _detect_framework(self, text: str) -> str:
        """Detect framework (UNIVERSAL)"""
        scores = {}
        
        for framework, patterns in self.framework_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, text, re.IGNORECASE))
            if score > 0:
                scores[framework] = score
        
        if scores:
            return max(scores, key=scores.get)
        return 'unknown'
    
    def _detect_os(self, text: str) -> str:
        """Detect operating system (UNIVERSAL)"""
        scores = {}
        
        for os_type, patterns in self.os_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, text, re.IGNORECASE))
            if score > 0:
                scores[os_type] = score
        
        if scores:
            return max(scores, key=scores.get)
        return 'unknown'