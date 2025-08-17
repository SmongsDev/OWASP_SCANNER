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
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.*\s*(WHERE|FROM|INTO|VALUES)\s*.*[\'\"]\s*\+\s*[\w\.\[\]]+',
            r'f[\'\"](SELECT|INSERT|UPDATE|DELETE).*\{.*\}.*[\'\"]\)',
            r'(cursor\.execute|execute)\s*\(\s*[\'\"](SELECT|INSERT|UPDATE|DELETE).*[\'\"]\s*\+',
            r'(cursor\.execute|execute)\s*\(\s*f[\'\"](SELECT|INSERT|UPDATE|DELETE).*\{.*\}',
            r'(query|sql)\s*=\s*[\'\"](SELECT|INSERT|UPDATE|DELETE).*[\'\"]\s*\+',
            r'(query|sql)\s*=\s*f[\'\"](SELECT|INSERT|UPDATE|DELETE).*\{.*\}'
        ]
        
        self.xss_patterns = [
            r'innerHTML\s*=\s*.*\+',
            r'document\.write\s*\(\s*.*\+',
            r'document\.writeln\s*\(\s*.*\+',
            r'\.append\s*\(\s*.*\+.*\)',
            r'\.html\s*\(\s*.*\+.*\)',
            r'outerHTML\s*=\s*.*\+',
            r'insertAdjacentHTML\s*\(\s*[\'\"]\w+[\'\"]\s*,\s*.*\+'
        ]
        
        self.command_injection_patterns = [
            r'(os\.system|subprocess\.|exec|eval)\s*\(\s*.*\+',
            r'(os\.popen|os\.spawn)\s*\(\s*.*\+',
            r'(system|shell_exec|exec|passthru)\s*\(\s*.*\.',
            r'(Runtime\.getRuntime\(\)\.exec)\s*\(\s*.*\+',
            r'(ProcessBuilder)\s*\(\s*.*\+'
        ]
        
        self.dangerous_functions = {
            'python': ['eval', 'exec', 'os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen'],
            'javascript': ['eval', 'Function', 'setTimeout', 'setInterval'],
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
        elif language == 'javascript':
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
        
        eval_pattern = r'eval\s*\(\s*.*\)'
        function_constructor_pattern = r'new\s+Function\s*\('
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            if re.search(eval_pattern, line, re.IGNORECASE):
                vuln = Vulnerability(
                    id=self._generate_vuln_id(),
                    owasp_category=OwaspCategory.A03.value,
                    type='code_injection',
                    severity=Severity.CRITICAL.value,
                    confidence=0.95,
                    file_path=file_path,
                    line_number=line_num,
                    column=line.find('eval'),
                    code_snippet=line[:80] + '...' if len(line) > 80 else line,
                    description='Code injection vulnerability: eval() can execute arbitrary JavaScript',
                    recommendation='Avoid using eval() or use JSON.parse() for safe data parsing',
                    cwe_id='CWE-94',
                    detection_method='regex_pattern_matching'
                )
                vulnerabilities.append(vuln)
            
            if re.search(function_constructor_pattern, line, re.IGNORECASE):
                vuln = Vulnerability(
                    id=self._generate_vuln_id(),
                    owasp_category=OwaspCategory.A03.value,
                    type='code_injection',
                    severity=Severity.HIGH.value,
                    confidence=0.85,
                    file_path=file_path,
                    line_number=line_num,
                    column=line.find('Function'),
                    code_snippet=line[:80] + '...' if len(line) > 80 else line,
                    description='Code injection vulnerability: Function constructor can execute arbitrary code',
                    recommendation='Avoid using Function constructor for dynamic code execution',
                    cwe_id='CWE-94',
                    detection_method='regex_pattern_matching'
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
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