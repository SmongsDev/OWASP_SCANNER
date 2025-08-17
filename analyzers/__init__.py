"""
OWASP Static Analysis Modules
"""

from .a03_injection import A03InjectionAnalyzer
from .a07_authentication import A07AuthenticationAnalyzer  
from .a06_components import A06ComponentAnalyzer

__all__ = ['A03InjectionAnalyzer', 'A07AuthenticationAnalyzer', 'A06ComponentAnalyzer']