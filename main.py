#!/usr/bin/env python3
"""
OWASP TOP 10 Static Analysis Scanner
Detects A03 (Injection), A07 (Authentication Failures), A06 (Vulnerable Components)
"""

import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from models import Vulnerability, Severity, OwaspCategory
from analyzers.a03_injection import A03InjectionAnalyzer
from analyzers.a07_authentication import A07AuthenticationAnalyzer
from analyzers.a06_components import A06ComponentAnalyzer


class OWASPStaticAnalyzer:
    def __init__(self):
        self.a03_analyzer = A03InjectionAnalyzer()
        self.a07_analyzer = A07AuthenticationAnalyzer()
        self.a06_analyzer = A06ComponentAnalyzer()
        self.vuln_counter = 0
    
    def analyze_project(self, project_json: dict) -> dict:
        start_time = time.time()
        vulnerabilities = []
        
        project_id = project_json.get('project_id', 'unknown')
        source_files = project_json.get('source_files', [])
        dependency_files = project_json.get('dependency_files', [])
        
        for source_file in source_files:
            file_vulnerabilities = self._analyze_source_file(source_file)
            vulnerabilities.extend(file_vulnerabilities)
        
        for dep_file in dependency_files:
            dep_vulnerabilities = self.a06_analyzer.analyze_dependencies(dep_file)
            vulnerabilities.extend(dep_vulnerabilities)
        
        scan_duration = time.time() - start_time
        
        return self._generate_report(project_id, vulnerabilities, scan_duration)
    
    def _analyze_source_file(self, source_file: dict) -> List[Vulnerability]:
        vulnerabilities = []
        file_path = source_file.get('path', '')
        language = source_file.get('language', '')
        content = source_file.get('content', '')
        
        vulnerabilities.extend(self.a03_analyzer.analyze(file_path, language, content))
        vulnerabilities.extend(self.a07_analyzer.analyze(file_path, language, content))
        
        return vulnerabilities
    
    def _generate_report(self, project_id: str, vulnerabilities: List[Vulnerability], scan_duration: float) -> dict:
        severity_counts = {
            'critical': len([v for v in vulnerabilities if v.severity == Severity.CRITICAL.value]),
            'high': len([v for v in vulnerabilities if v.severity == Severity.HIGH.value]),
            'medium': len([v for v in vulnerabilities if v.severity == Severity.MEDIUM.value]),
            'low': len([v for v in vulnerabilities if v.severity == Severity.LOW.value])
        }
        
        owasp_breakdown = {
            'A03_injection': len([v for v in vulnerabilities if v.owasp_category == OwaspCategory.A03.value]),
            'A07_authentication': len([v for v in vulnerabilities if v.owasp_category == OwaspCategory.A07.value]),
            'A06_components': len([v for v in vulnerabilities if v.owasp_category == OwaspCategory.A06.value])
        }
        
        recommendations = self._generate_recommendations(vulnerabilities)
        
        return {
            "scan_result": {
                "project_id": project_id,
                "scan_timestamp": datetime.utcnow().isoformat() + 'Z',
                "scan_duration_seconds": round(scan_duration, 2)
            },
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                **severity_counts,
                "owasp_breakdown": owasp_breakdown
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "owasp_category": v.owasp_category,
                    "type": v.type,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "column": v.column,
                    "code_snippet": v.code_snippet,
                    "description": v.description,
                    "recommendation": v.recommendation,
                    "cwe_id": v.cwe_id,
                    "detection_method": v.detection_method
                } for v in vulnerabilities
            ],
            "recommendations": recommendations
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        recommendations = []
        
        critical_vulns = [v for v in vulnerabilities if v.severity == Severity.CRITICAL.value]
        if critical_vulns:
            recommendations.append(f"Critical: Fix {len(critical_vulns)} critical vulnerabilities immediately")
        
        sql_injection_vulns = [v for v in vulnerabilities if v.type == 'sql_injection']
        if sql_injection_vulns:
            recommendations.append("High: Replace dynamic SQL queries with parameterized queries")
        
        auth_vulns = [v for v in vulnerabilities if v.owasp_category == OwaspCategory.A07.value]
        if auth_vulns:
            recommendations.append("High: Replace hardcoded credentials with environment variables")
        
        component_vulns = [v for v in vulnerabilities if v.owasp_category == OwaspCategory.A06.value]
        if component_vulns:
            recommendations.append("Medium: Update vulnerable dependencies to latest secure versions")
        
        return recommendations
    
    def _generate_vuln_id(self) -> str:
        self.vuln_counter += 1
        return f"VULN_{self.vuln_counter:03d}"


if __name__ == "__main__":
    scanner = OWASPStaticAnalyzer()
    
    sample_input = {
        "project_id": "test_project_001",
        "source_files": [
            {
                "path": "/backend/views/auth.py",
                "language": "python",
                "content": """import hashlib
def login_user(request):
    password = 'admin123'
    username = request.GET.get('username')
    query = f"SELECT * FROM users WHERE name='{username}'"
    cursor.execute(query)"""
            },
            {
                "path": "/frontend/js/user.js",
                "language": "javascript", 
                "content": """function displayUser(userData) {
    document.getElementById('user-info').innerHTML = userData.name;
    eval(userData.script);
}"""
            }
        ],
        "dependency_files": [
            {
                "type": "requirements.txt",
                "content": "Django==2.2.0\npsycopg2==2.9.3\nlodash==4.17.20"
            }
        ]
    }
    
    result = scanner.analyze_project(sample_input)
    print(json.dumps(result, indent=2))