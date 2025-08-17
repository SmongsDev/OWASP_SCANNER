"""
A07 Authentication Failures Analyzer
Detects hardcoded credentials, weak authentication patterns, and insecure password handling
"""

import re
import ast
import math
from collections import Counter
from typing import List, Dict, Tuple, Optional
from models import Vulnerability, Severity, OwaspCategory


class A07AuthenticationAnalyzer:
    def __init__(self):
        self.vuln_counter = 0
        
        self.credential_patterns = [
            r'(password|pwd|pass|secret|key|token|api_key|auth)\s*=\s*[\'\"]\w{3,}[\'\"]\s*',
            r'(PASSWORD|PWD|PASS|SECRET|KEY|TOKEN|API_KEY|AUTH)\s*=\s*[\'\"]\w{3,}[\'\"]\s*',
            r'(username|user|login)\s*=\s*[\'\"](admin|root|administrator|test|guest)[\'\"]\s*',
            r'(password|pwd|pass)\s*=\s*[\'\"](?:123|admin|password|root|test|guest|default)[\'\"]\s*'
        ]
        
        self.weak_hash_patterns = [
            r'(md5|MD5)\s*\(',
            r'(sha1|SHA1)\s*\(',
            r'hashlib\.(md5|sha1)\s*\(',
            r'MessageDigest\.getInstance\s*\(\s*[\'\"](?:MD5|SHA1|SHA-1)[\'\"]\s*\)',
            r'crypto\.createHash\s*\(\s*[\'\"](?:md5|sha1)[\'\"]\s*\)'
        ]
        
        self.insecure_session_patterns = [
            r'session\.permanent\s*=\s*False',
            r'session_cookie_secure\s*=\s*False',
            r'session_cookie_httponly\s*=\s*False',
            r'SESSION_COOKIE_SECURE\s*=\s*False',
            r'SESSION_COOKIE_HTTPONLY\s*=\s*False'
        ]
        
        self.weak_credential_keywords = [
            'admin', 'password', 'pass', '123', 'test', 'root', 'guest', 
            'default', 'demo', 'user', 'login', 'temp', 'sample'
        ]
        
        self.entropy_threshold = 3.0
    
    def analyze(self, file_path: str, language: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = content.split('\n')
        
        vulnerabilities.extend(self._detect_hardcoded_credentials(file_path, language, lines))
        vulnerabilities.extend(self._detect_weak_hashing(file_path, language, lines))
        vulnerabilities.extend(self._detect_insecure_session_config(file_path, language, lines))
        
        if language == 'python':
            vulnerabilities.extend(self._analyze_python_auth_patterns(file_path, content))
        elif language in ['javascript', 'typescript']:
            vulnerabilities.extend(self._analyze_javascript_auth_patterns(file_path, lines))
        
        return vulnerabilities
    
    def _detect_hardcoded_credentials(self, file_path: str, language: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//') or line.startswith('*'):
                continue
            
            for pattern in self.credential_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    credential_value = self._extract_credential_value(line, match)
                    
                    if credential_value and len(credential_value) > 2:
                        severity, confidence = self._assess_credential_risk(credential_value)
                        
                        vuln = Vulnerability(
                            id=self._generate_vuln_id(),
                            owasp_category=OwaspCategory.A07.value,
                            type='hardcoded_credential',
                            severity=severity,
                            confidence=confidence,
                            file_path=file_path,
                            line_number=line_num,
                            column=match.start(),
                            code_snippet=self._sanitize_credential_snippet(line),
                            description='Hardcoded credential detected in source code',
                            recommendation='Move credentials to environment variables or secure configuration',
                            cwe_id='CWE-798',
                            detection_method='regex_pattern_matching'
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_weak_hashing(self, file_path: str, language: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            for pattern in self.weak_hash_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    hash_type = match.group(1).upper()
                    
                    severity = Severity.MEDIUM.value
                    if hash_type in ['MD5']:
                        severity = Severity.HIGH.value
                    
                    vuln = Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A07.value,
                        type='weak_cryptography',
                        severity=severity,
                        confidence=0.9,
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start(),
                        code_snippet=line[:80] + '...' if len(line) > 80 else line,
                        description=f'Weak cryptographic hash algorithm detected: {hash_type}',
                        recommendation='Use stronger hash algorithms like SHA-256, bcrypt, or scrypt for passwords',
                        cwe_id='CWE-327',
                        detection_method='regex_pattern_matching'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_insecure_session_config(self, file_path: str, language: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            for pattern in self.insecure_session_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    config_type = self._extract_config_type(line)
                    
                    vuln = Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A07.value,
                        type='insecure_session_config',
                        severity=Severity.MEDIUM.value,
                        confidence=0.85,
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start(),
                        code_snippet=line[:80] + '...' if len(line) > 80 else line,
                        description=f'Insecure session configuration detected: {config_type}',
                        recommendation='Enable secure session configurations (secure, httponly flags)',
                        cwe_id='CWE-614',
                        detection_method='regex_pattern_matching'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_python_auth_patterns(self, file_path: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    vuln = self._check_assignment_credential(file_path, node)
                    if vuln:
                        vulnerabilities.append(vuln)
                elif isinstance(node, ast.Call):
                    vuln = self._check_auth_function_call(file_path, node)
                    if vuln:
                        vulnerabilities.append(vuln)
        except SyntaxError:
            pass
        
        return vulnerabilities
    
    def _analyze_javascript_auth_patterns(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        jwt_patterns = [
            r'jwt\.sign\s*\(\s*.*,\s*[\'\"]\w{1,10}[\'\"]\s*\)',
            r'jsonwebtoken\.sign\s*\(\s*.*,\s*[\'\"]\w{1,10}[\'\"]\s*\)'
        ]
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            for pattern in jwt_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    vuln = Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A07.value,
                        type='weak_jwt_secret',
                        severity=Severity.HIGH.value,
                        confidence=0.8,
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start(),
                        code_snippet=line[:80] + '...' if len(line) > 80 else line,
                        description='Weak JWT secret detected',
                        recommendation='Use strong, randomly generated JWT secrets with sufficient entropy',
                        cwe_id='CWE-326',
                        detection_method='regex_pattern_matching'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_credential_value(self, line: str, match) -> Optional[str]:
        try:
            value_start = line.find('=', match.start()) + 1
            value_part = line[value_start:].strip()
            
            quote_match = re.search(r'[\'\"](.*?)[\'\"]\s*', value_part)
            if quote_match:
                return quote_match.group(1)
            
            return None
        except:
            return None
    
    def _assess_credential_risk(self, credential: str) -> Tuple[str, float]:
        severity = Severity.MEDIUM.value
        confidence = 0.7
        
        if credential.lower() in self.weak_credential_keywords:
            severity = Severity.HIGH.value
            confidence = 0.95
        elif len(credential) < 6:
            severity = Severity.HIGH.value
            confidence = 0.9
        elif self._calculate_entropy(credential) < self.entropy_threshold:
            severity = Severity.HIGH.value
            confidence = 0.85
        elif len(credential) > 20 and self._calculate_entropy(credential) > 4.0:
            confidence = 0.8
        
        return severity, confidence
    
    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        text_length = len(text)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _sanitize_credential_snippet(self, line: str) -> str:
        sanitized = re.sub(r'([\'\"]\w*)[^\'\"]*([\'\"])', r'\1***\2', line)
        return sanitized[:80] + '...' if len(sanitized) > 80 else sanitized
    
    def _extract_config_type(self, line: str) -> str:
        if 'secure' in line.lower():
            return 'session_cookie_secure'
        elif 'httponly' in line.lower():
            return 'session_cookie_httponly'
        elif 'permanent' in line.lower():
            return 'session_permanent'
        else:
            return 'session_config'
    
    def _check_assignment_credential(self, file_path: str, node: ast.Assign) -> Optional[Vulnerability]:
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                if any(keyword in var_name for keyword in ['password', 'secret', 'key', 'token']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        credential = node.value.value
                        
                        if len(credential) > 2:
                            severity, confidence = self._assess_credential_risk(credential)
                            
                            return Vulnerability(
                                id=self._generate_vuln_id(),
                                owasp_category=OwaspCategory.A07.value,
                                type='hardcoded_credential',
                                severity=severity,
                                confidence=confidence,
                                file_path=file_path,
                                line_number=getattr(node, 'lineno', 0),
                                column=getattr(node, 'col_offset', 0),
                                code_snippet=f'{var_name} = "***"',
                                description=f'Hardcoded credential in variable: {var_name}',
                                recommendation='Move credential to environment variable or secure config',
                                cwe_id='CWE-798',
                                detection_method='ast_analysis'
                            )
        
        return None
    
    def _check_auth_function_call(self, file_path: str, node: ast.Call) -> Optional[Vulnerability]:
        func_name = self._get_function_name(node.func)
        
        auth_functions = ['authenticate', 'login', 'verify_password', 'check_password']
        
        if any(auth_func in func_name.lower() for auth_func in auth_functions):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.lower() in self.weak_credential_keywords:
                        return Vulnerability(
                            id=self._generate_vuln_id(),
                            owasp_category=OwaspCategory.A07.value,
                            type='weak_credential',
                            severity=Severity.HIGH.value,
                            confidence=0.9,
                            file_path=file_path,
                            line_number=getattr(node, 'lineno', 0),
                            column=getattr(node, 'col_offset', 0),
                            code_snippet=f'{func_name}("***")',
                            description=f'Weak credential used in {func_name}() function',
                            recommendation='Use strong, unique credentials',
                            cwe_id='CWE-521',
                            detection_method='ast_analysis'
                        )
        
        return None
    
    def _get_function_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_function_name(node.value)}.{node.attr}"
        else:
            return str(node)
    
    def _generate_vuln_id(self) -> str:
        self.vuln_counter += 1
        return f"A07_{self.vuln_counter:03d}"