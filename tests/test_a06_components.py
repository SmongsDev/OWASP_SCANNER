"""
Test cases for A06 Components Analyzer
"""

import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.a06_components import A06ComponentAnalyzer


class TestA06ComponentAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = A06ComponentAnalyzer()
    
    def test_requirements_txt_parsing(self):
        requirements_content = '''
Django==2.2.0
psycopg2==2.9.3
requests==2.25.0
# This is a comment
flask>=1.0.0
'''
        dep_file = {
            'type': 'requirements.txt',
            'content': requirements_content
        }
        
        dependencies = self.analyzer._parse_requirements_txt(requirements_content)
        self.assertGreaterEqual(len(dependencies), 3)
        
        django_found = any(dep[0] == 'django' and dep[1] == '2.2.0' for dep in dependencies)
        self.assertTrue(django_found)
    
    def test_package_json_parsing(self):
        package_json_content = '''
{
  "dependencies": {
    "express": "^4.17.1",
    "lodash": "4.17.20",
    "moment": "~2.29.0"
  },
  "devDependencies": {
    "jest": "^27.0.0"
  }
}
'''
        dependencies = self.analyzer._parse_package_json(package_json_content)
        self.assertGreaterEqual(len(dependencies), 3)
        
        lodash_found = any(dep[0] == 'lodash' and dep[1] == '4.17.20' for dep in dependencies)
        self.assertTrue(lodash_found)
    
    def test_vulnerable_component_detection(self):
        dep_file = {
            'type': 'requirements.txt',
            'content': 'Django==2.2.0\nlodash==4.17.15'
        }
        
        vulnerabilities = self.analyzer.analyze_dependencies(dep_file)
        
        vuln_components = [v for v in vulnerabilities if v.type == 'vulnerable_component']
        self.assertGreater(len(vuln_components), 0)
        
        critical_vulns = [v for v in vuln_components if v.severity == 'CRITICAL']
        self.assertGreaterEqual(len(critical_vulns), 0)
    
    def test_outdated_component_detection(self):
        dep_file = {
            'type': 'package.json',
            'content': '{"dependencies": {"express": "4.16.0", "lodash": "4.17.15"}}'
        }
        
        vulnerabilities = self.analyzer.analyze_dependencies(dep_file)
        
        outdated_components = [v for v in vulnerabilities if v.type == 'outdated_component']
        self.assertGreater(len(outdated_components), 0)
    
    def test_pom_xml_parsing(self):
        pom_xml_content = '''
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.18</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.12.6</version>
        </dependency>
    </dependencies>
</project>
'''
        dependencies = self.analyzer._parse_pom_xml(pom_xml_content)
        self.assertGreaterEqual(len(dependencies), 2)
        
        spring_found = any(dep[0] == 'spring-core' and dep[1] == '5.3.18' for dep in dependencies)
        jackson_found = any(dep[0] == 'jackson-databind' and dep[1] == '2.12.6' for dep in dependencies)
        
        self.assertTrue(spring_found)
        self.assertTrue(jackson_found)
    
    def test_version_comparison(self):
        versions_behind = self.analyzer._calculate_versions_behind('4.17.15', '4.17.21')
        self.assertGreater(versions_behind, 0)
        
        no_versions_behind = self.analyzer._calculate_versions_behind('4.17.21', '4.17.21')
        self.assertEqual(no_versions_behind, 0)
    
    def test_high_severity_vulnerabilities(self):
        dep_file = {
            'type': 'requirements.txt',
            'content': 'Django==2.2.0\n'
        }
        
        vulnerabilities = self.analyzer.analyze_dependencies(dep_file)
        
        high_severity = [v for v in vulnerabilities if v.severity == 'HIGH']
        self.assertGreater(len(high_severity), 0)
    
    def test_log4j_critical_vulnerability(self):
        dep_file = {
            'type': 'pom.xml',
            'content': '''
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
'''
        }
        
        vulnerabilities = self.analyzer.analyze_dependencies(dep_file)
        
        critical_vulns = [v for v in vulnerabilities if v.severity == 'CRITICAL']
        log4j_vulns = [v for v in critical_vulns if 'log4j' in v.code_snippet.lower()]
        
        self.assertGreater(len(log4j_vulns), 0)
    
    def test_confidence_scoring(self):
        dep_file = {
            'type': 'requirements.txt',
            'content': 'Django==2.2.0'
        }
        
        vulnerabilities = self.analyzer.analyze_dependencies(dep_file)
        
        vuln_components = [v for v in vulnerabilities if v.type == 'vulnerable_component']
        
        if vuln_components:
            self.assertGreaterEqual(vuln_components[0].confidence, 0.9)
    
    def test_empty_dependency_file(self):
        dep_file = {
            'type': 'requirements.txt',
            'content': ''
        }
        
        vulnerabilities = self.analyzer.analyze_dependencies(dep_file)
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_unsupported_file_type(self):
        dep_file = {
            'type': 'unknown.txt',
            'content': 'some content'
        }
        
        vulnerabilities = self.analyzer.analyze_dependencies(dep_file)
        self.assertEqual(len(vulnerabilities), 0)


if __name__ == '__main__':
    unittest.main()