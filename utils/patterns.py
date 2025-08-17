"""
Pattern matching utilities for vulnerability detection
"""

import re
from typing import List, Dict, Tuple, Optional


class PatternMatcher:
    def __init__(self):
        self.compiled_patterns = {}
    
    def compile_patterns(self, pattern_dict: Dict[str, List[str]]) -> None:
        for category, patterns in pattern_dict.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns
            ]
    
    def find_matches(self, text: str, category: str) -> List[Tuple[int, int, str]]:
        matches = []
        
        if category not in self.compiled_patterns:
            return matches
        
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.compiled_patterns[category]:
                for match in pattern.finditer(line):
                    matches.append((
                        line_num,
                        match.start(),
                        match.group(0)
                    ))
        
        return matches
    
    def is_pattern_match(self, text: str, pattern: str) -> bool:
        return bool(re.search(pattern, text, re.IGNORECASE))
    
    def extract_string_literals(self, code: str, language: str) -> List[str]:
        if language == 'python':
            return self._extract_python_strings(code)
        elif language in ['javascript', 'typescript']:
            return self._extract_js_strings(code)
        elif language == 'java':
            return self._extract_java_strings(code)
        else:
            return []
    
    def _extract_python_strings(self, code: str) -> List[str]:
        strings = []
        
        string_patterns = [
            r'[\'\"]{3}(.*?)[\'\"]{3}',
            r'[\'\"]((?:\\.|[^\'\"\\])*)[\'\"]\s*',
            r'f[\'\"]((?:\\.|[^\'\"\\])*)[\'\"]\s*'
        ]
        
        for pattern in string_patterns:
            matches = re.findall(pattern, code, re.DOTALL)
            strings.extend(matches)
        
        return strings
    
    def _extract_js_strings(self, code: str) -> List[str]:
        strings = []
        
        string_patterns = [
            r'[\'\"]((?:\\.|[^\'\"\\])*)[\'\"]\s*',
            r'`((?:\\.|[^`\\])*)`\s*'
        ]
        
        for pattern in string_patterns:
            matches = re.findall(pattern, code, re.DOTALL)
            strings.extend(matches)
        
        return strings
    
    def _extract_java_strings(self, code: str) -> List[str]:
        strings = []
        
        string_pattern = r'\"((?:\\.|[^\"\\])*)\"'
        matches = re.findall(string_pattern, code)
        strings.extend(matches)
        
        return strings
    
    def find_function_calls(self, code: str, language: str) -> List[Tuple[str, int, List[str]]]:
        if language == 'python':
            return self._find_python_function_calls(code)
        elif language in ['javascript', 'typescript']:
            return self._find_js_function_calls(code)
        else:
            return []
    
    def _find_python_function_calls(self, code: str) -> List[Tuple[str, int, List[str]]]:
        function_calls = []
        
        pattern = r'(\w+(?:\.\w+)*)\s*\((.*?)\)'
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(pattern, line)
            for match in matches:
                func_name = match.group(1)
                args_str = match.group(2)
                args = [arg.strip() for arg in args_str.split(',') if arg.strip()]
                
                function_calls.append((func_name, line_num, args))
        
        return function_calls
    
    def _find_js_function_calls(self, code: str) -> List[Tuple[str, int, List[str]]]:
        function_calls = []
        
        pattern = r'(\w+(?:\.\w+)*)\s*\((.*?)\)'
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(pattern, line)
            for match in matches:
                func_name = match.group(1)
                args_str = match.group(2)
                args = [arg.strip() for arg in args_str.split(',') if arg.strip()]
                
                function_calls.append((func_name, line_num, args))
        
        return function_calls
    
    def check_sql_keywords(self, text: str) -> bool:
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
            'ALTER', 'GRANT', 'REVOKE', 'UNION', 'WHERE', 'FROM'
        ]
        
        text_upper = text.upper()
        return any(keyword in text_upper for keyword in sql_keywords)
    
    def check_shell_metacharacters(self, text: str) -> bool:
        shell_chars = ['|', '&', ';', '$', '`', '(', ')', '{', '}', '[', ']', '>', '<']
        return any(char in text for char in shell_chars)
    
    def is_base64_encoded(self, text: str) -> bool:
        if len(text) < 4 or len(text) % 4 != 0:
            return False
        
        base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        return bool(re.match(base64_pattern, text))
    
    def extract_urls(self, text: str) -> List[str]:
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;!?]'
        return re.findall(url_pattern, text)
    
    def extract_ip_addresses(self, text: str) -> List[str]:
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return re.findall(ip_pattern, text)
    
    def extract_email_addresses(self, text: str) -> List[str]:
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)