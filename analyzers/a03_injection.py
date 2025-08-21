"""
A03 Injection Analyzer
Detects SQL Injection, XSS, and Command Injection vulnerabilities
"""

import re
import ast
from typing import List, Dict, Tuple, Optional
from models import Vulnerability, Severity, OwaspCategory


class A03InjectionAnalyzer:
    def __init__(self):
        self.vuln_counter = 0
        
        self.sql_patterns = [
            # Python SQL Injection patterns
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.*\s*(WHERE|FROM|INTO|VALUES)\s*.*[\'\"]\s*\+\s*[\w\.\[\]]+',
            r'f[\'\"](SELECT|INSERT|UPDATE|DELETE).*\{.*\}.*[\'\"]\)',
            r'(cursor\.execute|execute)\s*\(\s*[\'\"](SELECT|INSERT|UPDATE|DELETE).*[\'\"]\s*\+',
            r'(cursor\.execute|execute)\s*\(\s*f[\'\"](SELECT|INSERT|UPDATE|DELETE).*\{.*\}',
            r'(query|sql)\s*=\s*[\'\"](SELECT|INSERT|UPDATE|DELETE).*[\'\"]\s*\+',
            r'(query|sql)\s*=\s*f[\'\"](SELECT|INSERT|UPDATE|DELETE).*\{.*\}',
            
            # JavaScript/TypeScript SQL Injection patterns  
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.*\s*(WHERE|FROM|INTO|VALUES).*`[^`]*\$\{[^}]*\}',
            r'`(SELECT|INSERT|UPDATE|DELETE).*\$\{[^}]*\}.*`',
            r'(query|sql)\s*=\s*`(SELECT|INSERT|UPDATE|DELETE).*\$\{[^}]*\}',
            r'(connection\.query|db\.query|pool\.query)\s*\(\s*.*[+`]',
            r'(sequelize\.query|knex\.raw)\s*\(\s*.*[+`]',
            
            # Node.js ORM patterns (unsafe)
            r'\.where\s*\(\s*.*[+`]',
            r'\.having\s*\(\s*.*[+`]',
            r'\.orderBy\s*\(\s*.*[+`]'
        ]
        
        self.xss_patterns = [
            # DOM Manipulation (basic)
            r'innerHTML\s*=\s*.*[+`]',
            r'outerHTML\s*=\s*.*[+`]',
            r'insertAdjacentHTML\s*\([^,]+,\s*.*[+`]',
            r'insertAdjacentText\s*\([^,]+,\s*.*[+`]',
            
            # Document Methods
            r'document\.write\s*\(\s*.*[+`]',
            r'document\.writeln\s*\(\s*.*[+`]',
            
            # jQuery Methods
            r'\$\([^)]+\)\.html\s*\(\s*.*[+`]',
            r'\$\([^)]+\)\.append\s*\(\s*.*[+`]',
            r'\$\([^)]+\)\.prepend\s*\(\s*.*[+`]',
            r'\$\([^)]+\)\.after\s*\(\s*.*[+`]',
            r'\$\([^)]+\)\.before\s*\(\s*.*[+`]',
            
            # Template Literals (unsafe)
            r'innerHTML\s*=\s*`[^`]*\$\{[^}]*\}',
            r'outerHTML\s*=\s*`[^`]*\$\{[^}]*\}',
            
            # React dangerouslySetInnerHTML
            r'dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*.*[+`]',
            
            # Angular bypassSecurityTrustHtml
            r'bypassSecurityTrustHtml\s*\(\s*.*[+`]',
            
            # Event Handler Injection
            r'setAttribute\s*\(\s*[\'\"](on\w+)[\'\"]\s*,\s*.*[+`]',
            r'\w+\.on\w+\s*=\s*.*[+`]',
            
            # Original patterns
            r'\.append\s*\(\s*.*\+.*\)',
            r'\.html\s*\(\s*.*\+.*\)'
        ]
        
        self.command_injection_patterns = [
            # Python Command Injection
            r'(os\.system|subprocess\.|exec|eval)\s*\(\s*.*[+`]',
            r'(os\.popen|os\.spawn)\s*\(\s*.*[+`]',
            
            # JavaScript Command Injection
            r'eval\s*\(\s*.*[+`]',
            r'Function\s*\(\s*.*[+`]',
            r'setTimeout\s*\(\s*.*[+`]',
            r'setInterval\s*\(\s*.*[+`]',
            
            # Node.js Child Process
            r'child_process\.exec\s*\(\s*.*[+`]',
            r'child_process\.execSync\s*\(\s*.*[+`]',
            r'child_process\.spawn\s*\(\s*.*[+`]',
            r'require\s*\(\s*[\'\"](child_process)[\'\"].*\.exec\s*\(\s*.*[+`]',
            
            # Browser APIs (unsafe)
            r'fetch\s*\(\s*.*[+`]',
            r'XMLHttpRequest.*\.open\s*\([^,]+,\s*.*[+`]',
            
            # PHP Command Injection
            r'(system|shell_exec|exec|passthru)\s*\(\s*.*[+`.]',
            
            # Java Command Injection
            r'(Runtime\.getRuntime\(\)\.exec)\s*\(\s*.*[+`]',
            r'(ProcessBuilder)\s*\(\s*.*[+`]'
        ]
        
        self.dangerous_functions = {
            'python': ['eval', 'exec', 'os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen'],
            'javascript': [
                'eval', 'Function', 'setTimeout', 'setInterval',
                'child_process.exec', 'child_process.execSync', 'child_process.spawn',
                'vm.runInThisContext', 'vm.runInNewContext',
                'require', 'import'
            ],
            'typescript': [
                'eval', 'Function', 'setTimeout', 'setInterval',
                'child_process.exec', 'child_process.execSync', 'child_process.spawn',
                'vm.runInThisContext', 'vm.runInNewContext'
            ],
            'java': ['Runtime.getRuntime().exec', 'ProcessBuilder'],
            'c': ['system', 'popen', 'execl', 'execv'],
            'cpp': ['system', 'popen', 'execl', 'execv']
        }
    
    def analyze(self, file_path: str, language: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = content.split('\n')
        
        vulnerabilities.extend(self._detect_sql_injection(file_path, language, lines))
        vulnerabilities.extend(self._detect_xss(file_path, language, lines))
        vulnerabilities.extend(self._detect_command_injection(file_path, language, lines))
        
        if language == 'python':
            vulnerabilities.extend(self._analyze_python_ast(file_path, content))
        elif language in ['javascript', 'typescript']:
            vulnerabilities.extend(self._analyze_javascript_patterns(file_path, lines))
        
        return vulnerabilities
    
    def _detect_sql_injection(self, file_path: str, language: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
                
            for pattern in self.sql_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    vuln = Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A03.value,
                        type='sql_injection',
                        severity=Severity.HIGH.value,
                        confidence=0.9,
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start(),
                        code_snippet=line[:80] + '...' if len(line) > 80 else line,
                        description='SQL Injection vulnerability detected in string concatenation/formatting',
                        recommendation='Use parameterized queries or ORM methods to prevent SQL injection',
                        cwe_id='CWE-89',
                        detection_method='regex_pattern_matching'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_xss(self, file_path: str, language: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        if language not in ['javascript', 'typescript']:
            return vulnerabilities
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
                
            for pattern in self.xss_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    confidence = 0.8
                    if 'innerHTML' in line or 'document.write' in line:
                        confidence = 0.95
                    
                    vuln = Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A03.value,
                        type='xss',
                        severity=Severity.MEDIUM.value,
                        confidence=confidence,
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start(),
                        code_snippet=line[:80] + '...' if len(line) > 80 else line,
                        description='Cross-Site Scripting (XSS) vulnerability detected in DOM manipulation',
                        recommendation='Use safe DOM manipulation methods and escape user input',
                        cwe_id='CWE-79',
                        detection_method='regex_pattern_matching'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_command_injection(self, file_path: str, language: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
                
            for pattern in self.command_injection_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    severity = Severity.HIGH.value
                    if 'eval(' in line or 'exec(' in line:
                        severity = Severity.CRITICAL.value
                    
                    vuln = Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A03.value,
                        type='command_injection',
                        severity=severity,
                        confidence=0.85,
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start(),
                        code_snippet=line[:80] + '...' if len(line) > 80 else line,
                        description='Command Injection vulnerability detected in system call',
                        recommendation='Use safe system call methods and validate user input',
                        cwe_id='CWE-78',
                        detection_method='regex_pattern_matching'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_python_ast(self, file_path: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    vuln = self._check_dangerous_call(file_path, node)
                    if vuln:
                        vulnerabilities.append(vuln)
                elif isinstance(node, ast.JoinedStr):
                    vuln = self._check_f_string_injection(file_path, node)
                    if vuln:
                        vulnerabilities.append(vuln)
        except SyntaxError:
            pass
        
        return vulnerabilities
    
    def _check_dangerous_call(self, file_path: str, node: ast.Call) -> Optional[Vulnerability]:
        func_name = self._get_function_name(node.func)
        
        dangerous_funcs = ['eval', 'exec', 'compile']
        if func_name in dangerous_funcs:
            return Vulnerability(
                id=self._generate_vuln_id(),
                owasp_category=OwaspCategory.A03.value,
                type='code_injection',
                severity=Severity.CRITICAL.value,
                confidence=0.95,
                file_path=file_path,
                line_number=getattr(node, 'lineno', 0),
                column=getattr(node, 'col_offset', 0),
                code_snippet=f'{func_name}() call detected',
                description=f'Code injection vulnerability: {func_name}() can execute arbitrary code',
                recommendation=f'Avoid using {func_name}() or use ast.literal_eval() for safe evaluation',
                cwe_id='CWE-94',
                detection_method='ast_analysis'
            )
        
        return None
    
    def _check_f_string_injection(self, file_path: str, node: ast.JoinedStr) -> Optional[Vulnerability]:
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if hasattr(value.value, 'id') and 'query' in str(value.value.id).lower():
                    return Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A03.value,
                        type='sql_injection',
                        severity=Severity.HIGH.value,
                        confidence=0.8,
                        file_path=file_path,
                        line_number=getattr(node, 'lineno', 0),
                        column=getattr(node, 'col_offset', 0),
                        code_snippet='f-string SQL query detected',
                        description='SQL Injection vulnerability in f-string formatting',
                        recommendation='Use parameterized queries instead of f-string formatting',
                        cwe_id='CWE-89',
                        detection_method='ast_analysis'
                    )
        
        return None
    
    def _analyze_javascript_patterns(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Enhanced JavaScript vulnerability patterns
        js_patterns = {
            'code_injection': [
                (r'eval\s*\(\s*.*\)', 'eval() can execute arbitrary JavaScript', 'CRITICAL', 0.95),
                (r'new\s+Function\s*\(', 'Function constructor can execute arbitrary code', 'HIGH', 0.85),
                (r'setTimeout\s*\(\s*[\'\"]\s*.*\s*[\'\"]', 'setTimeout with string can execute code', 'HIGH', 0.8),
                (r'setInterval\s*\(\s*[\'\"]\s*.*\s*[\'\"]', 'setInterval with string can execute code', 'HIGH', 0.8),
                (r'vm\.runInThisContext\s*\(', 'VM module can execute arbitrary code', 'CRITICAL', 0.9),
                (r'vm\.runInNewContext\s*\(', 'VM module can execute arbitrary code', 'CRITICAL', 0.9)
            ],
            'server_side_injection': [
                (r'child_process\.exec\s*\(\s*.*[+`]', 'Command injection via child_process.exec', 'CRITICAL', 0.9),
                (r'child_process\.execSync\s*\(\s*.*[+`]', 'Command injection via child_process.execSync', 'CRITICAL', 0.9),
                (r'child_process\.spawn\s*\(\s*.*[+`]', 'Command injection via child_process.spawn', 'HIGH', 0.85),
                (r'require\s*\(\s*.*[+`]', 'Dynamic require can load malicious modules', 'HIGH', 0.8)
            ],
            'prototype_pollution': [
                (r'JSON\.parse\s*\(\s*.*[+`]', 'JSON.parse with user input can cause prototype pollution', 'MEDIUM', 0.7),
                (r'Object\.assign\s*\(\s*.*[+`]', 'Object.assign with user input can modify prototypes', 'MEDIUM', 0.65),
                (r'\w+\[.*\]\s*=\s*.*[+`]', 'Dynamic property assignment can pollute prototypes', 'LOW', 0.6)
            ],
            'url_injection': [
                (r'fetch\s*\(\s*.*[+`]', 'SSRF vulnerability via dynamic URL in fetch', 'MEDIUM', 0.75),
                (r'XMLHttpRequest.*\.open\s*\([^,]+,\s*.*[+`]', 'SSRF vulnerability via dynamic URL in XMLHttpRequest', 'MEDIUM', 0.75),
                (r'window\.location\s*=\s*.*[+`]', 'Open redirect via dynamic location assignment', 'MEDIUM', 0.7),
                (r'location\.href\s*=\s*.*[+`]', 'Open redirect via dynamic href assignment', 'MEDIUM', 0.7)
            ],
            'nosql_injection': [
                (r'db\.collection\s*\([^)]+\)\.find\s*\(\s*.*[+`]', 'NoSQL injection in MongoDB query', 'HIGH', 0.8),
                (r'\.findOne\s*\(\s*.*[+`]', 'NoSQL injection in findOne query', 'HIGH', 0.8),
                (r'\.aggregate\s*\(\s*.*[+`]', 'NoSQL injection in aggregation pipeline', 'HIGH', 0.75)
            ]
        }
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            
            for vuln_type, patterns in js_patterns.items():
                for pattern, description, severity, confidence in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Map string severity to enum value
                        severity_value = getattr(Severity, severity).value
                        
                        vuln = Vulnerability(
                            id=self._generate_vuln_id(),
                            owasp_category=OwaspCategory.A03.value,
                            type=vuln_type,
                            severity=severity_value,
                            confidence=confidence,
                            file_path=file_path,
                            line_number=line_num,
                            column=match.start(),
                            code_snippet=line[:80] + '...' if len(line) > 80 else line,
                            description=f'JavaScript vulnerability: {description}',
                            recommendation=self._get_js_recommendation(vuln_type),
                            cwe_id=self._get_js_cwe_id(vuln_type),
                            detection_method='regex_pattern_matching'
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_js_recommendation(self, vuln_type: str) -> str:
        recommendations = {
            'code_injection': 'Avoid eval(), Function constructor, and string-based timeouts. Use JSON.parse() for data parsing',
            'server_side_injection': 'Use subprocess methods with argument arrays, avoid shell injection',
            'prototype_pollution': 'Validate and sanitize object properties, use Map instead of plain objects',
            'url_injection': 'Validate and whitelist URLs, use URL constructor for parsing',
            'nosql_injection': 'Use parameterized queries and validate input data types'
        }
        return recommendations.get(vuln_type, 'Review and validate user input handling')
    
    def _get_js_cwe_id(self, vuln_type: str) -> str:
        cwe_mappings = {
            'code_injection': 'CWE-94',
            'server_side_injection': 'CWE-78',
            'prototype_pollution': 'CWE-1321',
            'url_injection': 'CWE-918',
            'nosql_injection': 'CWE-943'
        }
        return cwe_mappings.get(vuln_type, 'CWE-20')
    
    def _get_function_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_function_name(node.value)}.{node.attr}"
        else:
            return str(node)
    
    def _generate_vuln_id(self) -> str:
        self.vuln_counter += 1
        return f"A03_{self.vuln_counter:03d}"