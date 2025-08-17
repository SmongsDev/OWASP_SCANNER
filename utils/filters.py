"""
False positive filtering utilities
"""

import re
from typing import List, Set
from models import Vulnerability


class FalsePositiveFilter:
    def __init__(self):
        self.test_file_patterns = [
            r'.*test.*\.py$',
            r'.*_test\.py$',
            r'.*tests?/.*',
            r'.*spec\.js$',
            r'.*\.test\.js$',
            r'.*\.spec\.ts$',
            r'.*\.test\.ts$'
        ]
        
        self.comment_patterns = [
            r'^\s*#.*',
            r'^\s*//.*',
            r'^\s*/\*.*\*/\s*$',
            r'.*//.*TODO.*',
            r'.*#.*FIXME.*'
        ]
        
        self.safe_sql_patterns = [
            r'cursor\.execute\s*\(\s*[\'\"]\w+[\'\"]\s*,\s*\(',
            r'\.prepare\s*\(\s*[\'\"]\w+[\'\"]\s*\)',
            r'PreparedStatement',
            r'parameterized',
            r'\.query\s*\(\s*[\'\"]\w+[\'\"]\s*,\s*\['
        ]
        
        self.safe_contexts = [
            'logging',
            'debug',
            'documentation',
            'configuration',
            'example'
        ]
        
        self.known_safe_functions = {
            'python': [
                'logging.info',
                'logging.debug',
                'logging.warning',
                'print',
                'logger.info'
            ],
            'javascript': [
                'console.log',
                'console.debug',
                'console.info',
                'JSON.stringify'
            ]
        }
    
    def filter_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        filtered = []
        
        for vuln in vulnerabilities:
            if not self.is_false_positive(vuln):
                filtered.append(vuln)
        
        return filtered
    
    def is_false_positive(self, vuln: Vulnerability) -> bool:
        if self.is_test_file(vuln.file_path):
            return True
        
        if self.is_comment_only(vuln.code_snippet):
            return True
        
        if self.is_safe_sql_pattern(vuln.code_snippet, vuln.type):
            return True
        
        if self.is_safe_context(vuln.file_path, vuln.code_snippet):
            return True
        
        if self.is_known_safe_function(vuln.code_snippet):
            return True
        
        if self.is_documentation_example(vuln.file_path, vuln.code_snippet):
            return True
        
        return False
    
    def is_test_file(self, file_path: str) -> bool:
        for pattern in self.test_file_patterns:
            if re.match(pattern, file_path, re.IGNORECASE):
                return True
        return False
    
    def is_comment_only(self, code_snippet: str) -> bool:
        lines = code_snippet.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            is_comment = False
            for pattern in self.comment_patterns:
                if re.match(pattern, line):
                    is_comment = True
                    break
            
            if not is_comment:
                return False
        
        return True
    
    def is_safe_sql_pattern(self, code_snippet: str, vuln_type: str) -> bool:
        if vuln_type != 'sql_injection':
            return False
        
        for pattern in self.safe_sql_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return True
        
        return False
    
    def is_safe_context(self, file_path: str, code_snippet: str) -> bool:
        file_path_lower = file_path.lower()
        code_lower = code_snippet.lower()
        
        for context in self.safe_contexts:
            if context in file_path_lower or context in code_lower:
                return True
        
        return False
    
    def is_known_safe_function(self, code_snippet: str) -> bool:
        code_lower = code_snippet.lower()
        
        for lang, functions in self.known_safe_functions.items():
            for func in functions:
                if func in code_lower:
                    return True
        
        return False
    
    def is_documentation_example(self, file_path: str, code_snippet: str) -> bool:
        doc_indicators = [
            'readme', 'docs/', 'documentation',
            'example', 'sample', 'demo',
            '.md', '.rst', '.txt'
        ]
        
        file_path_lower = file_path.lower()
        code_lower = code_snippet.lower()
        
        for indicator in doc_indicators:
            if indicator in file_path_lower:
                return True
        
        if 'example' in code_lower or 'sample' in code_lower:
            return True
        
        return False
    
    def calculate_false_positive_score(self, vuln: Vulnerability) -> float:
        score = 0.0
        
        if self.is_test_file(vuln.file_path):
            score += 0.8
        
        if self.is_comment_only(vuln.code_snippet):
            score += 0.7
        
        if self.is_safe_context(vuln.file_path, vuln.code_snippet):
            score += 0.5
        
        if self.is_documentation_example(vuln.file_path, vuln.code_snippet):
            score += 0.6
        
        if vuln.type == 'sql_injection' and self.is_safe_sql_pattern(vuln.code_snippet, vuln.type):
            score += 0.9
        
        return min(score, 1.0)
    
    def filter_by_confidence_threshold(self, 
                                     vulnerabilities: List[Vulnerability],
                                     threshold: float = 0.5) -> List[Vulnerability]:
        return [vuln for vuln in vulnerabilities if vuln.confidence >= threshold]
    
    def remove_duplicates(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln.file_path, vuln.line_number, vuln.type, vuln.code_snippet)
            
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def filter_by_severity(self, 
                         vulnerabilities: List[Vulnerability],
                         min_severity: str = 'LOW') -> List[Vulnerability]:
        severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_index = severity_order.index(min_severity)
        
        return [
            vuln for vuln in vulnerabilities
            if severity_order.index(vuln.severity) >= min_index
        ]