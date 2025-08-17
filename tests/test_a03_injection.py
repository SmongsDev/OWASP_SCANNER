"""
Test cases for A03 Injection Analyzer
"""

import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.a03_injection import A03InjectionAnalyzer


class TestA03InjectionAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = A03InjectionAnalyzer()
    
    def test_sql_injection_detection_basic(self):
        test_code = '''
def get_user(username):
    query = f"SELECT * FROM users WHERE name='{username}'"
    cursor.execute(query)
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        sql_vulns = [v for v in vulnerabilities if v.type == 'sql_injection']
        self.assertGreater(len(sql_vulns), 0)
        self.assertEqual(sql_vulns[0].severity, 'HIGH')
    
    def test_sql_injection_string_concatenation(self):
        test_code = '''
def login(user_id):
    sql = "SELECT * FROM users WHERE id=" + str(user_id)
    execute_query(sql)
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        sql_vulns = [v for v in vulnerabilities if v.type == 'sql_injection']
        self.assertGreater(len(sql_vulns), 0)
    
    def test_xss_detection_javascript(self):
        test_code = '''
function updateProfile(userData) {
    document.getElementById('profile').innerHTML = userData.bio;
    eval(userData.script);
}
'''
        vulnerabilities = self.analyzer.analyze('/test/file.js', 'javascript', test_code)
        
        xss_vulns = [v for v in vulnerabilities if v.type == 'xss']
        code_vulns = [v for v in vulnerabilities if v.type == 'code_injection']
        
        self.assertGreater(len(xss_vulns), 0)
        self.assertGreater(len(code_vulns), 0)
    
    def test_command_injection_detection(self):
        test_code = '''
import os

def process_file(filename):
    os.system("cat " + filename)
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        cmd_vulns = [v for v in vulnerabilities if v.type == 'command_injection']
        self.assertGreater(len(cmd_vulns), 0)
        self.assertEqual(cmd_vulns[0].severity, 'HIGH')
    
    def test_eval_detection_critical(self):
        test_code = '''
def execute_code(user_input):
    result = eval(user_input)
    return result
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        code_vulns = [v for v in vulnerabilities if v.type == 'command_injection']
        self.assertGreater(len(code_vulns), 0)
        self.assertEqual(code_vulns[0].severity, 'CRITICAL')
    
    def test_no_false_positives_safe_code(self):
        test_code = '''
def safe_query(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    
def safe_output():
    element.textContent = user_data
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_javascript_eval_detection(self):
        test_code = '''
function processData(data) {
    var result = eval("(" + data + ")");
    return result;
}
'''
        vulnerabilities = self.analyzer.analyze('/test/file.js', 'javascript', test_code)
        
        code_vulns = [v for v in vulnerabilities if v.type == 'code_injection']
        self.assertGreater(len(code_vulns), 0)
        self.assertEqual(code_vulns[0].severity, 'CRITICAL')
    
    def test_function_constructor_detection(self):
        test_code = '''
function createDynamicFunction(code) {
    return new Function(code);
}
'''
        vulnerabilities = self.analyzer.analyze('/test/file.js', 'javascript', test_code)
        
        code_vulns = [v for v in vulnerabilities if v.type == 'code_injection']
        self.assertGreater(len(code_vulns), 0)
        self.assertEqual(code_vulns[0].severity, 'HIGH')
    
    def test_confidence_scoring(self):
        test_code = '''
def high_confidence_vuln():
    query = f"DELETE FROM users WHERE id={user_id}"
    cursor.execute(query)
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        sql_vulns = [v for v in vulnerabilities if v.type == 'sql_injection']
        self.assertGreater(len(sql_vulns), 0)
        self.assertGreaterEqual(sql_vulns[0].confidence, 0.8)
    
    def test_multiple_vulnerabilities_same_line(self):
        test_code = '''
def dangerous_function(user_input):
    eval(f"SELECT * FROM users WHERE name='{user_input}'")
'''
        vulnerabilities = self.analyzer.analyze('/test/file.py', 'python', test_code)
        
        self.assertGreaterEqual(len(vulnerabilities), 1)


if __name__ == '__main__':
    unittest.main()