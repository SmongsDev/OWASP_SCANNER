"""
A06 Vulnerable and Outdated Components Analyzer
Detects vulnerable dependencies and outdated packages
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional
from models import Vulnerability, Severity, OwaspCategory


class A06ComponentAnalyzer:
    def __init__(self):
        self.vuln_counter = 0
        
        self.vulnerability_db = {
            'django': {
                '2.2.0': [{'cve': 'CVE-2019-14232', 'severity': 'HIGH', 'description': 'SQL injection in Django admin'}],
                '2.2.1': [{'cve': 'CVE-2019-14233', 'severity': 'MEDIUM', 'description': 'XSS vulnerability'}],
                '3.0.0': [{'cve': 'CVE-2020-9402', 'severity': 'HIGH', 'description': 'SQL injection via JSONField'}],
                '4.0.0': [{'cve': 'CVE-2021-45115', 'severity': 'MEDIUM', 'description': 'DoS via file uploads'}]
            },
            'lodash': {
                '4.17.20': [{'cve': 'CVE-2021-23337', 'severity': 'HIGH', 'description': 'Command injection vulnerability'}],
                '4.17.19': [{'cve': 'CVE-2020-8203', 'severity': 'HIGH', 'description': 'Prototype pollution'}],
                '4.17.15': [{'cve': 'CVE-2019-10744', 'severity': 'CRITICAL', 'description': 'Prototype pollution'}]
            },
            'express': {
                '4.17.1': [{'cve': 'CVE-2022-24999', 'severity': 'MEDIUM', 'description': 'Open redirect vulnerability'}],
                '4.16.0': [{'cve': 'CVE-2017-16119', 'severity': 'LOW', 'description': 'Debug information exposure'}]
            },
            # JavaScript/Node.js specific vulnerabilities
            'axios': {
                '0.21.1': [{'cve': 'CVE-2021-3749', 'severity': 'HIGH', 'description': 'SSRF vulnerability in axios'}],
                '0.19.0': [{'cve': 'CVE-2020-28168', 'severity': 'MEDIUM', 'description': 'SSRF via malicious URL'}]
            },
            'node-fetch': {
                '2.6.6': [{'cve': 'CVE-2022-0235', 'severity': 'HIGH', 'description': 'Exposure of sensitive information'}],
                '2.6.0': [{'cve': 'CVE-2020-15168', 'severity': 'MEDIUM', 'description': 'Size limit bypass'}]
            },
            'jsonwebtoken': {
                '8.5.1': [{'cve': 'CVE-2022-23529', 'severity': 'HIGH', 'description': 'Token verification bypass'}],
                '8.5.0': [{'cve': 'CVE-2022-23540', 'severity': 'MEDIUM', 'description': 'Algorithm confusion'}]
            },
            'socket.io': {
                '4.4.1': [{'cve': 'CVE-2022-2421', 'severity': 'MEDIUM', 'description': 'CORS bypass vulnerability'}],
                '3.1.0': [{'cve': 'CVE-2020-36048', 'severity': 'HIGH', 'description': 'Insufficient input validation'}]
            },
            'mongoose': {
                '5.13.14': [{'cve': 'CVE-2022-24304', 'severity': 'HIGH', 'description': 'Prototype pollution in query parsing'}],
                '5.9.0': [{'cve': 'CVE-2020-7731', 'severity': 'MEDIUM', 'description': 'ReDoS in validation'}]
            },
            'sequelize': {
                '6.6.2': [{'cve': 'CVE-2021-23436', 'severity': 'HIGH', 'description': 'SQL injection in JSON query'}],
                '5.21.0': [{'cve': 'CVE-2020-15237', 'severity': 'MEDIUM', 'description': 'SQL injection in JSONB'}]
            },
            'ws': {
                '7.5.5': [{'cve': 'CVE-2021-32640', 'severity': 'HIGH', 'description': 'ReDoS in sec-websocket-protocol header'}],
                '6.2.1': [{'cve': 'CVE-2020-7662', 'severity': 'MEDIUM', 'description': 'ReDoS in validation'}]
            },
            'moment': {
                '2.29.1': [{'cve': 'CVE-2022-24785', 'severity': 'HIGH', 'description': 'Path traversal via locale'}],
                '2.27.0': [{'cve': 'CVE-2020-15366', 'severity': 'MEDIUM', 'description': 'ReDoS in parsing'}]
            },
            'helmet': {
                '4.6.0': [{'cve': 'CVE-2021-23406', 'severity': 'MEDIUM', 'description': 'CSP bypass via iframe-src'}]
            },
            'passport': {
                '0.4.1': [{'cve': 'CVE-2021-23334', 'severity': 'MEDIUM', 'description': 'Session fixation vulnerability'}]
            },
            'cors': {
                '2.8.5': [{'cve': 'CVE-2020-7729', 'severity': 'MEDIUM', 'description': 'CORS misconfiguration'}]
            },
            'multer': {
                '1.4.2': [{'cve': 'CVE-2021-23362', 'severity': 'HIGH', 'description': 'Directory traversal in file upload'}]
            },
            'psycopg2': {
                '2.8.0': [{'cve': 'CVE-2020-25659', 'severity': 'MEDIUM', 'description': 'Buffer overflow'}]
            },
            'spring-core': {
                '5.3.18': [{'cve': 'CVE-2022-22965', 'severity': 'CRITICAL', 'description': 'Spring4Shell RCE'}],
                '5.3.17': [{'cve': 'CVE-2022-22950', 'severity': 'MEDIUM', 'description': 'SpEL expression injection'}]
            },
            'jackson-databind': {
                '2.12.6': [{'cve': 'CVE-2020-36518', 'severity': 'HIGH', 'description': 'Deserialization vulnerability'}],
                '2.10.0': [{'cve': 'CVE-2019-20330', 'severity': 'HIGH', 'description': 'Unsafe deserialization'}]
            },
            'log4j-core': {
                '2.14.1': [{'cve': 'CVE-2021-44228', 'severity': 'CRITICAL', 'description': 'Log4Shell RCE vulnerability'}],
                '2.15.0': [{'cve': 'CVE-2021-45046', 'severity': 'HIGH', 'description': 'DoS and RCE via JNDI'}]
            },
            'requests': {
                '2.25.0': [{'cve': 'CVE-2023-32681', 'severity': 'MEDIUM', 'description': 'Proxy-Authorization header leak'}],
                '2.20.0': [{'cve': 'CVE-2018-18074', 'severity': 'HIGH', 'description': 'Credentials leak in redirect'}]
            }
        }
        
        self.latest_versions = {
            'django': '4.2.7',
            'lodash': '4.17.21',
            'express': '4.18.2',
            'psycopg2': '2.9.7',
            'spring-core': '6.0.13',
            'jackson-databind': '2.15.3',
            'log4j-core': '2.20.0',
            'requests': '2.31.0',
            # JavaScript/Node.js latest versions
            'axios': '1.6.2',
            'node-fetch': '3.3.2',
            'jsonwebtoken': '9.0.2',
            'socket.io': '4.7.4',
            'mongoose': '8.0.3',
            'sequelize': '6.35.2',
            'ws': '8.15.1',
            'moment': '2.29.4',
            'helmet': '7.1.0',
            'passport': '0.7.0',
            'cors': '2.8.5',
            'multer': '1.4.5',
            'react': '18.2.0',
            'vue': '3.3.8',
            'angular': '17.0.0',
            'next': '14.0.4',
            'webpack': '5.89.0',
            'babel-core': '7.23.5',
            'typescript': '5.3.3'
        }
    
    def analyze_dependencies(self, dependency_file: dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        file_type = dependency_file.get('type', '')
        content = dependency_file.get('content', '')
        
        if file_type == 'requirements.txt':
            dependencies = self._parse_requirements_txt(content)
        elif file_type == 'package.json':
            dependencies = self._parse_package_json(content)
        elif file_type == 'pom.xml':
            dependencies = self._parse_pom_xml(content)
        elif file_type == 'Gemfile':
            dependencies = self._parse_gemfile(content)
        elif file_type == 'composer.json':
            dependencies = self._parse_composer_json(content)
        else:
            return vulnerabilities
        
        for package_name, package_version in dependencies:
            vulns = self._check_vulnerability(package_name, package_version, file_type)
            vulnerabilities.extend(vulns)
            
            outdated_vuln = self._check_outdated_package(package_name, package_version, file_type)
            if outdated_vuln:
                vulnerabilities.append(outdated_vuln)
        
        return vulnerabilities
    
    def _parse_requirements_txt(self, content: str) -> List[Tuple[str, str]]:
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            match = re.match(r'^([a-zA-Z0-9\-_.]+)([<>=!]+)([0-9.]+)', line)
            if match:
                package_name = match.group(1).lower()
                package_version = match.group(3)
                dependencies.append((package_name, package_version))
        
        return dependencies
    
    def _parse_package_json(self, content: str) -> List[Tuple[str, str]]:
        dependencies = []
        
        try:
            data = json.loads(content)
            
            for dep_type in ['dependencies', 'devDependencies']:
                deps = data.get(dep_type, {})
                for package_name, version_spec in deps.items():
                    package_version = re.sub(r'[^\d.]', '', version_spec)
                    if package_version:
                        dependencies.append((package_name.lower(), package_version))
        
        except json.JSONDecodeError:
            pass
        
        return dependencies
    
    def _parse_pom_xml(self, content: str) -> List[Tuple[str, str]]:
        dependencies = []
        
        try:
            root = ET.fromstring(content)
            
            ns = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
            
            for dependency in root.findall('.//mvn:dependency', ns):
                artifact_elem = dependency.find('mvn:artifactId', ns)
                version_elem = dependency.find('mvn:version', ns)
                
                if artifact_elem is not None and version_elem is not None:
                    artifact_id = artifact_elem.text.lower()
                    dep_version = version_elem.text
                    
                    if dep_version and not dep_version.startswith('${'):
                        dependencies.append((artifact_id, dep_version))
        
        except ET.ParseError:
            pass
        
        return dependencies
    
    def _parse_gemfile(self, content: str) -> List[Tuple[str, str]]:
        dependencies = []
        
        gem_pattern = r'gem\s+[\'\"]([\w\-]+)[\'\"]\s*,\s*[\'\"]([\d.]+)[\'\"]\s*'
        
        for match in re.finditer(gem_pattern, content):
            gem_name = match.group(1).lower()
            gem_version = match.group(2)
            dependencies.append((gem_name, gem_version))
        
        return dependencies
    
    def _parse_composer_json(self, content: str) -> List[Tuple[str, str]]:
        dependencies = []
        
        try:
            data = json.loads(content)
            
            for dep_type in ['require', 'require-dev']:
                deps = data.get(dep_type, {})
                for package_name, version_spec in deps.items():
                    if '/' in package_name:
                        package_version = re.sub(r'[^\d.]', '', version_spec)
                        if package_version:
                            dependencies.append((package_name.lower(), package_version))
        
        except json.JSONDecodeError:
            pass
        
        return dependencies
    
    def _check_vulnerability(self, package_name: str, package_version: str, file_type: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        if package_name in self.vulnerability_db:
            package_vulns = self.vulnerability_db[package_name]
            
            for vuln_version, vulns in package_vulns.items():
                try:
                    if self._compare_versions(package_version, vuln_version) <= 0:
                        for vuln_info in vulns:
                            vuln = Vulnerability(
                                id=self._generate_vuln_id(),
                                owasp_category=OwaspCategory.A06.value,
                                type='vulnerable_component',
                                severity=vuln_info['severity'],
                                confidence=0.95,
                                file_path=f'dependency_file.{file_type}',
                                line_number=1,
                                column=1,
                                code_snippet=f'{package_name}=={package_version}',
                                description=f"Vulnerable component: {package_name} {package_version} - {vuln_info['description']}",
                                recommendation=f'Update {package_name} to a secure version',
                                cwe_id=vuln_info.get('cwe', 'CWE-937'),
                                detection_method='vulnerability_database'
                            )
                            vulnerabilities.append(vuln)
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _check_outdated_package(self, package_name: str, package_version: str, file_type: str) -> Optional[Vulnerability]:
        if package_name in self.latest_versions:
            latest_version = self.latest_versions[package_name]
            
            try:
                if self._compare_versions(package_version, latest_version) < 0:
                    versions_behind = self._calculate_versions_behind(package_version, latest_version)
                    
                    severity = Severity.LOW.value
                    if versions_behind >= 5:
                        severity = Severity.MEDIUM.value
                    if versions_behind >= 10:
                        severity = Severity.HIGH.value
                    
                    return Vulnerability(
                        id=self._generate_vuln_id(),
                        owasp_category=OwaspCategory.A06.value,
                        type='outdated_component',
                        severity=severity,
                        confidence=0.8,
                        file_path=f'dependency_file.{file_type}',
                        line_number=1,
                        column=1,
                        code_snippet=f'{package_name}=={package_version}',
                        description=f'Outdated component: {package_name} {package_version} (latest: {latest_version})',
                        recommendation=f'Update {package_name} to version {latest_version}',
                        cwe_id='CWE-1104',
                        detection_method='version_comparison'
                    )
            
            except Exception:
                pass
        
        return None
    
    def _calculate_versions_behind(self, current_version: str, latest_version: str) -> int:
        try:
            current_parts = [int(x) for x in current_version.split('.')]
            latest_parts = [int(x) for x in latest_version.split('.')]
            
            max_len = max(len(current_parts), len(latest_parts))
            current_parts.extend([0] * (max_len - len(current_parts)))
            latest_parts.extend([0] * (max_len - len(latest_parts)))
            
            versions_behind = 0
            for i in range(max_len):
                if latest_parts[i] > current_parts[i]:
                    versions_behind += (latest_parts[i] - current_parts[i]) * (10 ** (max_len - i - 1))
                elif latest_parts[i] < current_parts[i]:
                    break
            
            return min(versions_behind, 20)
        
        except:
            return 1
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        
        except:
            return 0
    
    def _generate_vuln_id(self) -> str:
        self.vuln_counter += 1
        return f"A06_{self.vuln_counter:03d}"