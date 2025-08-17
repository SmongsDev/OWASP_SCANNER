"""
Integration tests for OWASP Static Analysis Scanner
"""

import unittest
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import OWASPStaticAnalyzer


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.scanner = OWASPStaticAnalyzer()
    
    def test_full_project_scan(self):
        project_data = {
            "project_id": "test_project_001",
            "source_files": [
                {
                    "path": "/backend/views/auth.py",
                    "language": "python",
                    "content": '''import hashlib
def login_user(request):
    password = 'admin123'
    username = request.GET.get('username')
    query = f"SELECT * FROM users WHERE name='{username}'"
    cursor.execute(query)
    hash_obj = hashlib.md5(password.encode())
    return hash_obj.hexdigest()'''
                },
                {
                    "path": "/frontend/js/user.js",
                    "language": "javascript",
                    "content": '''function displayUser(userData) {
    document.getElementById('user-info').innerHTML = userData.name;
    eval(userData.script);
    const token = jwt.sign(payload, "weak");
}'''
                }
            ],
            "dependency_files": [
                {
                    "type": "requirements.txt",
                    "content": "Django==2.2.0\npsycopg2==2.9.3\nlodash==4.17.20"
                },
                {
                    "type": "package.json",
                    "content": '{"dependencies": {"express": "4.17.1", "lodash": "4.17.15"}}'
                }
            ]
        }
        
        result = self.scanner.analyze_project(project_data)
        
        self.assertIn('scan_result', result)
        self.assertIn('summary', result)
        self.assertIn('vulnerabilities', result)
        self.assertIn('recommendations', result)
        
        self.assertEqual(result['scan_result']['project_id'], 'test_project_001')
        self.assertGreater(result['summary']['total_vulnerabilities'], 0)
        
        self.assertGreater(result['summary']['owasp_breakdown']['A03_injection'], 0)
        self.assertGreater(result['summary']['owasp_breakdown']['A07_authentication'], 0)
        self.assertGreater(result['summary']['owasp_breakdown']['A06_components'], 0)
    
    def test_severity_distribution(self):
        project_data = {
            "project_id": "severity_test",
            "source_files": [
                {
                    "path": "/critical.py",
                    "language": "python",
                    "content": 'eval(user_input)'
                },
                {
                    "path": "/high.py", 
                    "language": "python",
                    "content": 'password = "admin123"'
                },
                {
                    "path": "/medium.js",
                    "language": "javascript",
                    "content": 'element.innerHTML = userData;'
                }
            ],
            "dependency_files": []
        }
        
        result = self.scanner.analyze_project(project_data)
        
        summary = result['summary']
        
        self.assertGreaterEqual(summary['critical'], 1)
        self.assertGreaterEqual(summary['high'], 1)
        self.assertGreaterEqual(summary['medium'], 1)
    
    def test_vulnerability_details(self):
        project_data = {
            "project_id": "detail_test",
            "source_files": [
                {
                    "path": "/test.py",
                    "language": "python",
                    "content": 'query = f"SELECT * FROM users WHERE id={user_id}"'
                }
            ],
            "dependency_files": []
        }
        
        result = self.scanner.analyze_project(project_data)
        
        vulnerabilities = result['vulnerabilities']
        self.assertGreater(len(vulnerabilities), 0)
        
        vuln = vulnerabilities[0]
        required_fields = [
            'id', 'owasp_category', 'type', 'severity', 'confidence',
            'file_path', 'line_number', 'column', 'code_snippet',
            'description', 'recommendation', 'cwe_id', 'detection_method'
        ]
        
        for field in required_fields:
            self.assertIn(field, vuln)
    
    def test_recommendations_generation(self):
        project_data = {
            "project_id": "recommendations_test",
            "source_files": [
                {
                    "path": "/critical.py",
                    "language": "python", 
                    "content": 'eval(user_input)'
                },
                {
                    "path": "/auth.py",
                    "language": "python",
                    "content": 'password = "admin123"'
                }
            ],
            "dependency_files": [
                {
                    "type": "requirements.txt",
                    "content": "Django==2.2.0"
                }
            ]
        }
        
        result = self.scanner.analyze_project(project_data)
        
        recommendations = result['recommendations']
        self.assertGreater(len(recommendations), 0)
        
        has_critical_rec = any('Critical' in rec for rec in recommendations)
        has_auth_rec = any('credential' in rec.lower() for rec in recommendations)
        has_component_rec = any('dependencies' in rec.lower() for rec in recommendations)
        
        self.assertTrue(has_critical_rec or has_auth_rec or has_component_rec)
    
    def test_performance_timing(self):
        project_data = {
            "project_id": "performance_test",
            "source_files": [
                {
                    "path": f"/file_{i}.py",
                    "language": "python",
                    "content": f'password = "secret_{i}"'
                } for i in range(10)
            ],
            "dependency_files": []
        }
        
        result = self.scanner.analyze_project(project_data)
        
        scan_duration = result['scan_result']['scan_duration_seconds']
        self.assertLess(scan_duration, 10.0)
        self.assertGreater(scan_duration, 0.0)
    
    def test_json_output_format(self):
        project_data = {
            "project_id": "json_test",
            "source_files": [
                {
                    "path": "/test.py",
                    "language": "python",
                    "content": 'password = "test123"'
                }
            ],
            "dependency_files": []
        }
        
        result = self.scanner.analyze_project(project_data)
        
        try:
            json_str = json.dumps(result)
            parsed_back = json.loads(json_str)
            self.assertEqual(result, parsed_back)
        except Exception as e:
            self.fail(f"Result is not JSON serializable: {e}")
    
    def test_empty_project(self):
        project_data = {
            "project_id": "empty_test",
            "source_files": [],
            "dependency_files": []
        }
        
        result = self.scanner.analyze_project(project_data)
        
        self.assertEqual(result['summary']['total_vulnerabilities'], 0)
        self.assertEqual(len(result['vulnerabilities']), 0)
    
    def test_mixed_languages(self):
        project_data = {
            "project_id": "mixed_test",
            "source_files": [
                {
                    "path": "/backend.py",
                    "language": "python",
                    "content": 'query = f"SELECT * FROM users WHERE id={user_id}"'
                },
                {
                    "path": "/frontend.js",
                    "language": "javascript",
                    "content": 'document.write(userInput);'
                },
                {
                    "path": "/api.java",
                    "language": "java",
                    "content": 'String password = "hardcoded";'
                }
            ],
            "dependency_files": []
        }
        
        result = self.scanner.analyze_project(project_data)
        
        vulnerabilities = result['vulnerabilities']
        
        python_vulns = [v for v in vulnerabilities if '/backend.py' in v['file_path']]
        js_vulns = [v for v in vulnerabilities if '/frontend.js' in v['file_path']]
        
        self.assertGreater(len(python_vulns), 0)
        self.assertGreater(len(js_vulns), 0)
    
    def test_confidence_scores(self):
        project_data = {
            "project_id": "confidence_test",
            "source_files": [
                {
                    "path": "/high_confidence.py",
                    "language": "python",
                    "content": 'eval(user_input)'
                }
            ],
            "dependency_files": []
        }
        
        result = self.scanner.analyze_project(project_data)
        
        vulnerabilities = result['vulnerabilities']
        
        for vuln in vulnerabilities:
            self.assertIsInstance(vuln['confidence'], (int, float))
            self.assertGreaterEqual(vuln['confidence'], 0.0)
            self.assertLessEqual(vuln['confidence'], 1.0)


if __name__ == '__main__':
    unittest.main()