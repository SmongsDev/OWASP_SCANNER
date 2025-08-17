"""
Confidence scoring utilities for vulnerability assessment
"""

import math
from typing import Dict, List, Optional
from collections import Counter


class ConfidenceCalculator:
    def __init__(self):
        self.base_confidence = {
            'exact_match': 0.95,
            'pattern_match': 0.8,
            'heuristic_match': 0.6,
            'weak_indicator': 0.4
        }
        
        self.language_modifiers = {
            'python': 1.0,
            'javascript': 0.9,
            'typescript': 0.9,
            'java': 0.85,
            'c': 0.8,
            'cpp': 0.8,
            'php': 0.75
        }
        
        self.context_modifiers = {
            'test_file': 0.3,
            'comment_only': 0.2,
            'configuration': 0.7,
            'production_code': 1.0,
            'example_code': 0.4
        }
    
    def calculate_injection_confidence(self, 
                                    pattern_type: str,
                                    language: str,
                                    context: str,
                                    has_user_input: bool,
                                    has_sanitization: bool) -> float:
        base = self.base_confidence.get(pattern_type, 0.5)
        
        lang_modifier = self.language_modifiers.get(language, 0.7)
        context_modifier = self.context_modifiers.get(context, 1.0)
        
        confidence = base * lang_modifier * context_modifier
        
        if has_user_input:
            confidence *= 1.3
        
        if has_sanitization:
            confidence *= 0.4
        
        return min(confidence, 1.0)
    
    def calculate_auth_confidence(self,
                                credential_value: str,
                                entropy: float,
                                is_default_credential: bool,
                                variable_name: str) -> float:
        base_confidence = 0.7
        
        if is_default_credential:
            base_confidence = 0.95
        elif entropy < 2.0:
            base_confidence = 0.9
        elif entropy < 3.0:
            base_confidence = 0.8
        elif entropy > 4.5:
            base_confidence = 0.6
        
        suspicious_names = ['password', 'secret', 'key', 'token', 'auth']
        if any(name in variable_name.lower() for name in suspicious_names):
            base_confidence *= 1.2
        
        if len(credential_value) < 4:
            base_confidence *= 1.1
        elif len(credential_value) > 50:
            base_confidence *= 0.8
        
        return min(base_confidence, 1.0)
    
    def calculate_component_confidence(self,
                                     has_known_vuln: bool,
                                     versions_behind: int,
                                     is_direct_dependency: bool) -> float:
        if has_known_vuln:
            base_confidence = 0.95
        else:
            base_confidence = 0.7
        
        if versions_behind > 10:
            base_confidence *= 1.1
        elif versions_behind > 5:
            base_confidence *= 1.05
        
        if is_direct_dependency:
            base_confidence *= 1.0
        else:
            base_confidence *= 0.8
        
        return min(base_confidence, 1.0)
    
    def calculate_entropy(self, text: str) -> float:
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
    
    def assess_false_positive_risk(self,
                                 file_path: str,
                                 code_snippet: str,
                                 vulnerability_type: str) -> float:
        risk = 0.0
        
        if 'test' in file_path.lower():
            risk += 0.5
        
        if 'example' in file_path.lower() or 'demo' in file_path.lower():
            risk += 0.4
        
        if 'comment' in code_snippet or '//' in code_snippet or '#' in code_snippet:
            risk += 0.3
        
        comment_patterns = ['TODO', 'FIXME', 'NOTE', 'XXX', 'HACK']
        if any(pattern in code_snippet.upper() for pattern in comment_patterns):
            risk += 0.2
        
        if vulnerability_type == 'sql_injection':
            safe_functions = ['cursor.execute', 'prepared_statement', 'parameterized']
            if any(func in code_snippet.lower() for func in safe_functions):
                risk += 0.3
        
        return min(risk, 1.0)
    
    def adjust_confidence_for_context(self,
                                    base_confidence: float,
                                    file_path: str,
                                    line_content: str) -> float:
        adjusted = base_confidence
        
        context = self.determine_context(file_path, line_content)
        context_modifier = self.context_modifiers.get(context, 1.0)
        
        adjusted *= context_modifier
        
        false_positive_risk = self.assess_false_positive_risk(
            file_path, line_content, 'generic'
        )
        adjusted *= (1.0 - false_positive_risk)
        
        return max(min(adjusted, 1.0), 0.1)
    
    def determine_context(self, file_path: str, line_content: str) -> str:
        file_path_lower = file_path.lower()
        
        if 'test' in file_path_lower:
            return 'test_file'
        elif 'config' in file_path_lower or 'setting' in file_path_lower:
            return 'configuration'
        elif 'example' in file_path_lower or 'demo' in file_path_lower:
            return 'example_code'
        elif line_content.strip().startswith(('#', '//', '/*')):
            return 'comment_only'
        else:
            return 'production_code'
    
    def combine_confidence_scores(self, scores: List[float], method: str = 'weighted_average') -> float:
        if not scores:
            return 0.0
        
        if method == 'max':
            return max(scores)
        elif method == 'min':
            return min(scores)
        elif method == 'average':
            return sum(scores) / len(scores)
        elif method == 'weighted_average':
            weights = [i + 1 for i in range(len(scores))]
            weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
            total_weight = sum(weights)
            return weighted_sum / total_weight
        else:
            return sum(scores) / len(scores)
    
    def normalize_confidence(self, confidence: float) -> float:
        return max(0.0, min(1.0, confidence))