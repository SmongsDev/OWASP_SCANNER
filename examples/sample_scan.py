#!/usr/bin/env python3
"""
Sample usage of OWASP Static Analysis Scanner
"""

import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import OWASPStaticAnalyzer


def run_sample_scan():
    scanner = OWASPStaticAnalyzer()
    
    sample_project = {
        "project_id": "sample_webapp_2024",
        "source_files": [
            {
                "path": "/backend/auth/login.py",
                "language": "python",
                "content": '''
import hashlib
import sqlite3

def authenticate_user(username, password):
    # Hardcoded database password - VULNERABILITY
    db_password = "admin123"
    
    # SQL Injection vulnerability - user input directly in query
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    
    # This is vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    
    if user:
        # Weak hashing algorithm
        password_hash = hashlib.md5(password.encode()).hexdigest()
        return {"authenticated": True, "hash": password_hash}
    
    return {"authenticated": False}

def reset_password():
    # Another hardcoded credential
    admin_token = "secret_reset_token_123"
    return admin_token
'''
            },
            {
                "path": "/frontend/js/profile.js",
                "language": "javascript",
                "content": '''
function updateUserProfile(userData) {
    // XSS vulnerability - direct HTML injection
    document.getElementById('profile-name').innerHTML = userData.name;
    document.getElementById('profile-bio').innerHTML = userData.bio;
    
    // Code injection vulnerability
    if (userData.preferences) {
        eval("var prefs = " + userData.preferences);
    }
    
    // Weak JWT secret
    const jwt = require('jsonwebtoken');
    const token = jwt.sign(userData, "weak_secret");
    
    return token;
}

function executeUserScript(scriptCode) {
    // Another code injection point
    return new Function(scriptCode)();
}
'''
            },
            {
                "path": "/config/database.py",
                "language": "python",
                "content": '''
import os

class DatabaseConfig:
    # These should use environment variables instead
    DB_HOST = "localhost"
    DB_USER = "root"
    DB_PASSWORD = "password123"  # Hardcoded password
    API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
    
    # Insecure session configuration
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
'''
            },
            {
                "path": "/utils/admin.py",
                "language": "python",
                "content": '''
import subprocess
import os

def execute_system_command(user_command):
    # Command injection vulnerability
    result = os.system("ls -la " + user_command)
    return result

def run_backup(backup_path):
    # Another command injection point
    subprocess.call(f"tar -czf backup.tar.gz {backup_path}", shell=True)

def process_file(filename):
    # Safe example - this should not trigger
    with open(filename, 'r') as f:
        content = f.read()
    return content.strip()
'''
            }
        ],
        "dependency_files": [
            {
                "type": "requirements.txt",
                "content": '''
Django==2.2.0
Flask==1.0.0
requests==2.20.0
psycopg2==2.8.0
Pillow==8.3.0
cryptography==3.4.0
'''
            },
            {
                "type": "package.json",
                "content": '''
{
  "name": "sample-webapp",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.15",
    "moment": "2.29.0",
    "jsonwebtoken": "8.5.0"
  },
  "devDependencies": {
    "jest": "26.0.0",
    "webpack": "4.44.0"
  }
}
'''
            },
            {
                "type": "pom.xml",
                "content": '''
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>sample-webapp</artifactId>
    <version>1.0.0</version>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.18</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.12.6</version>
        </dependency>
    </dependencies>
</project>
'''
            }
        ]
    }
    
    print("🔍 Starting OWASP Static Analysis Scan...")
    print("=" * 60)
    
    result = scanner.analyze_project(sample_project)
    
    print(f"📊 Scan Results for Project: {result['scan_result']['project_id']}")
    print(f"⏱️  Scan Duration: {result['scan_result']['scan_duration_seconds']} seconds")
    print()
    
    summary = result['summary']
    print("📈 Vulnerability Summary:")
    print(f"   Total Vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"   🔴 Critical: {summary['critical']}")
    print(f"   🟠 High: {summary['high']}")
    print(f"   🟡 Medium: {summary['medium']}")
    print(f"   🟢 Low: {summary['low']}")
    print()
    
    print("🛡️ OWASP Categories:")
    owasp = summary['owasp_breakdown']
    print(f"   A03 (Injection): {owasp['A03_injection']}")
    print(f"   A07 (Authentication): {owasp['A07_authentication']}")
    print(f"   A06 (Components): {owasp['A06_components']}")
    print()
    
    print("🔍 Top Vulnerabilities:")
    print("-" * 60)
    
    for i, vuln in enumerate(result['vulnerabilities'][:10], 1):
        print(f"{i}. {vuln['type'].upper()} ({vuln['severity']})")
        print(f"   File: {vuln['file_path']}:{vuln['line_number']}")
        print(f"   Description: {vuln['description']}")
        print(f"   Confidence: {vuln['confidence']:.2f}")
        print(f"   Code: {vuln['code_snippet'][:50]}...")
        print()
    
    print("💡 Recommendations:")
    print("-" * 60)
    for i, rec in enumerate(result['recommendations'], 1):
        print(f"{i}. {rec}")
    
    print()
    print("📋 Full JSON Report:")
    print("=" * 60)
    print(json.dumps(result, indent=2))
    
    return result


if __name__ == "__main__":
    try:
        scan_result = run_sample_scan()
        print("\n✅ Scan completed successfully!")
        
        total_vulns = scan_result['summary']['total_vulnerabilities']
        if total_vulns > 0:
            print(f"⚠️  Found {total_vulns} vulnerabilities that need attention.")
        else:
            print("🎉 No vulnerabilities detected!")
            
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        sys.exit(1)