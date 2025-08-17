# OWASP TOP 10 Static Analysis Scanner

A comprehensive static analysis tool that detects OWASP TOP 10 vulnerabilities in source code, focusing on:
- **A03**: Injection (SQL Injection, XSS, Command Injection)
- **A07**: Identification and Authentication Failures
- **A06**: Vulnerable and Outdated Components

## 🚀 Features

- **Multi-language Support**: Python, JavaScript, TypeScript, Java, C/C++
- **AST-based Analysis**: Deep code structure analysis for accurate detection
- **Dependency Scanning**: Analyzes requirements.txt, package.json, pom.xml
- **Confidence Scoring**: Advanced algorithms to minimize false positives
- **Comprehensive Reporting**: Detailed JSON reports with recommendations

## 📦 Installation

```bash
git clone <repository-url>
cd OWASP_SCANNER
pip install -r requirements.txt
```

## 🔧 Usage

### Basic Usage

```python
from main import OWASPStaticAnalyzer

scanner = OWASPStaticAnalyzer()

project_data = {
    "project_id": "my_project",
    "source_files": [
        {
            "path": "/app/views.py",
            "language": "python",
            "content": "query = f\"SELECT * FROM users WHERE id={user_id}\""
        }
    ],
    "dependency_files": [
        {
            "type": "requirements.txt",
            "content": "Django==2.2.0\\nrequests==2.20.0"
        }
    ]
}

result = scanner.analyze_project(project_data)
print(json.dumps(result, indent=2))
```

### Command Line Usage

```bash
python examples/sample_scan.py
```

## 🧪 Running Tests

```bash
# Run all tests
python -m unittest discover tests/

# Run specific test modules
python -m unittest tests.test_a03_injection
python -m unittest tests.test_a07_authentication
python -m unittest tests.test_a06_components
python -m unittest tests.test_integration
```

## 📊 Input Format

```json
{
  "project_id": "unique_project_id",
  "source_files": [
    {
      "path": "/backend/views/auth.py",
      "language": "python",
      "content": "source code content here"
    }
  ],
  "dependency_files": [
    {
      "type": "requirements.txt",
      "content": "Django==4.1.2\\npsycopg2==2.9.3"
    }
  ]
}
```

## 📈 Output Format

```json
{
  "scan_result": {
    "project_id": "unique_project_id",
    "scan_timestamp": "2025-01-15T10:35:00Z",
    "scan_duration_seconds": 2.5
  },
  "summary": {
    "total_vulnerabilities": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1,
    "owasp_breakdown": {
      "A03_injection": 3,
      "A07_authentication": 1,
      "A06_components": 1
    }
  },
  "vulnerabilities": [
    {
      "id": "VULN_001",
      "owasp_category": "A03",
      "type": "sql_injection",
      "severity": "HIGH",
      "confidence": 0.95,
      "file_path": "/backend/views/auth.py",
      "line_number": 7,
      "column": 15,
      "code_snippet": "f\"SELECT * FROM users WHERE name='{username}'\"",
      "description": "SQL Injection vulnerability detected",
      "recommendation": "Use parameterized queries",
      "cwe_id": "CWE-89",
      "detection_method": "regex_pattern_matching"
    }
  ],
  "recommendations": [
    "Critical: Fix SQL injection vulnerabilities immediately",
    "High: Replace hardcoded credentials with environment variables"
  ]
}
```

## 🔍 Detection Capabilities

### A03 - Injection
- **SQL Injection**: String concatenation, f-strings, dynamic queries
- **XSS**: innerHTML, document.write, DOM manipulation
- **Command Injection**: os.system, subprocess, eval, exec

### A07 - Authentication Failures
- **Hardcoded Credentials**: Passwords, API keys, secrets in code
- **Weak Cryptography**: MD5, SHA1, weak hashing algorithms
- **Session Security**: Insecure session configurations

### A06 - Vulnerable Components
- **Known Vulnerabilities**: CVE database matching
- **Outdated Dependencies**: Version comparison analysis
- **Multiple Formats**: requirements.txt, package.json, pom.xml

## 🎯 Accuracy Features

- **AST Analysis**: Python and JavaScript syntax tree parsing
- **Context Awareness**: Distinguishes test code from production
- **False Positive Filtering**: Advanced heuristics to reduce noise
- **Confidence Scoring**: Each vulnerability includes confidence level
- **Entropy Analysis**: Detects weak credentials using Shannon entropy

## 📁 Project Structure

```
OWASP_SCANNER/
├── main.py                 # Main scanner class
├── analyzers/
│   ├── a03_injection.py    # Injection vulnerability detection
│   ├── a07_authentication.py # Authentication failure detection
│   └── a06_components.py   # Component vulnerability detection
├── utils/
│   ├── patterns.py         # Pattern matching utilities
│   ├── confidence.py       # Confidence calculation
│   └── filters.py          # False positive filtering
├── tests/                  # Comprehensive test suite
├── examples/               # Usage examples
└── requirements.txt
```

## 🔧 Customization

### Adding New Patterns

```python
# Add to analyzers/a03_injection.py
custom_patterns = [
    r'custom_dangerous_function\s*\(\s*.*\+',
    r'another_pattern_here'
]
```

### Adjusting Confidence Scores

```python
# Modify in utils/confidence.py
def calculate_custom_confidence(pattern_type, context):
    base_confidence = 0.8
    # Custom logic here
    return base_confidence
```

## 📋 Supported File Types

### Source Code
- Python (.py)
- JavaScript (.js)
- TypeScript (.ts)
- Java (.java)
- C/C++ (.c, .cpp)

### Dependency Files
- requirements.txt (Python)
- package.json (Node.js)
- pom.xml (Maven/Java)
- Gemfile (Ruby)
- composer.json (PHP)

## 🚨 Vulnerability Database

Built-in database includes:
- Django vulnerabilities (CVE-2019-14232, CVE-2020-9402)
- Node.js package vulnerabilities (Lodash, Express)
- Java vulnerabilities (Spring, Jackson, Log4j)
- Python package vulnerabilities

## 🔒 Security Best Practices

- Never commit hardcoded credentials
- Use parameterized queries for database access
- Implement proper input validation and sanitization
- Keep dependencies updated to latest secure versions
- Use strong cryptographic algorithms (SHA-256+, bcrypt)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is for defensive security purposes only. Use responsibly and in accordance with applicable laws and regulations.

## 🆘 Support

For issues and feature requests, please create an issue in the repository.

---

**⚠️ Important**: This tool is designed for defensive security analysis only. Do not use for malicious purposes.