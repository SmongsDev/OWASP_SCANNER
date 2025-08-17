"""
Test cases for A07 Authentication Analyzer
"""

import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.a07_authentication import A07AuthenticationAnalyzer


class TestA07AuthenticationAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = A07AuthenticationAnalyzer()
    
    def test_hardcoded_password_detection(self):
        test_code = '''
def authenticate_user():
    password = "admin123"
    secret_key = "my_secret_key_123"
    return check_password(password)
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        cred_vulns = [v for v in vulnerabilities if v.type == 'hardcoded_credential']
        self.assertGreaterEqual(len(cred_vulns), 1)
    
    def test_weak_default_credentials(self):
        test_code = '''
def setup_admin():
    username = "admin"
    password = "password"
    api_key = "123456"
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        cred_vulns = [v for v in vulnerabilities if v.type == 'hardcoded_credential']
        high_severity_vulns = [v for v in cred_vulns if v.severity == 'HIGH']
        self.assertGreater(len(high_severity_vulns), 0)
    
    def test_weak_hashing_detection(self):
        test_code = '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def old_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        hash_vulns = [v for v in vulnerabilities if v.type == 'weak_cryptography']
        self.assertGreaterEqual(len(hash_vulns), 2)
    
    def test_insecure_session_config(self):
        test_code = '''
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
session.permanent = False
'''
        vulnerabilities = self.analyzer.analyze('/test/config.py', 'python', test_code)
        
        session_vulns = [v for v in vulnerabilities if v.type == 'insecure_session_config']
        self.assertGreaterEqual(len(session_vulns), 2)
    
    def test_weak_jwt_secret_javascript(self):
        test_code = '''
const jwt = require('jsonwebtoken');

function generateToken(payload) {
    return jwt.sign(payload, "secret123");
}
'''
        vulnerabilities = self.analyzer.analyze('/test/file.js', 'javascript', test_code)
        
        jwt_vulns = [v for v in vulnerabilities if v.type == 'weak_jwt_secret']
        self.assertGreater(len(jwt_vulns), 0)
        self.assertEqual(jwt_vulns[0].severity, 'HIGH')
    
    def test_entropy_calculation(self):
        low_entropy = self.analyzer._calculate_entropy("aaaaaa")
        high_entropy = self.analyzer._calculate_entropy("Ax9#mP2$kL")
        
        self.assertLess(low_entropy, 2.0)
        self.assertGreater(high_entropy, 3.0)
    
    def test_credential_risk_assessment(self):
        severity_weak, confidence_weak = self.analyzer._assess_credential_risk("admin")
        severity_strong, confidence_strong = self.analyzer._assess_credential_risk("Kx9#mP2$kL8@nQ5!")
        
        self.assertEqual(severity_weak, 'HIGH')
        self.assertGreater(confidence_weak, 0.9)
        
        self.assertEqual(severity_strong, 'MEDIUM')
        self.assertLess(confidence_strong, 0.9)
    
    def test_no_false_positives_comments(self):
        test_code = '''
# password = "admin123"  # This is just a comment
"""
Example usage:
password = "secret123"
"""
def safe_function():
    pass
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_safe_environment_variables(self):
        test_code = '''
import os

def get_credentials():
    password = os.environ.get('DB_PASSWORD')
    api_key = os.getenv('API_KEY')
    return password, api_key
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        cred_vulns = [v for v in vulnerabilities if v.type == 'hardcoded_credential']
        self.assertEqual(len(cred_vulns), 0)
    
    def test_credential_sanitization(self):
        test_code = '''
def login():
    password = "secret123"
    return authenticate(password)
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        cred_vulns = [v for v in vulnerabilities if v.type == 'hardcoded_credential']
        self.assertGreater(len(cred_vulns), 0)
        
        snippet = cred_vulns[0].code_snippet
        self.assertIn('***', snippet)
        self.assertNotIn('secret123', snippet)
    
    def test_multiple_credential_types(self):
        test_code = '''
class Config:
    SECRET_KEY = "my_flask_secret"
    API_TOKEN = "abc123def456"
    DATABASE_PASSWORD = "db_pass_2023"
'''
        vulnerabilities = self.analyzer.analyze('/test/config.py', 'python', test_code)
        
        cred_vulns = [v for v in vulnerabilities if v.type == 'hardcoded_credential']
        self.assertGreaterEqual(len(cred_vulns), 3)


if __name__ == '__main__':
    unittest.main()