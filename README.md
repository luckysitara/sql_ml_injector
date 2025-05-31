# SQL Injector v2.0 - Professional SQL Injection Testing Tool

A comprehensive, professional-grade SQL injection vulnerability scanner with a comprehensive payload database and automated report generation. This tool focuses on traditional security testing for enhanced vulnerability detection and professional security reporting.

## ⚠️ Legal Notice

**CRITICAL**: This tool is intended for authorized security testing only. Only use this tool on:
- Systems you own
- Systems you have explicit written permission to test
- Bug bounty programs that explicitly allow automated testing
- Authorized penetration testing engagements

Unauthorized testing is illegal and unethical. The developers are not responsible for any misuse of this tool.

## 🚀 Project Overview

SQL Injector v2.0 is a security testing platform that focuses on SQL injection vulnerability detection through:

### 🔧 **Advanced Testing Capabilities**
- **Comprehensive Payload Database**: 10,000+ SQL injection payloads across 18+ categories
- **Multi-Database Support**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and NoSQL injection techniques
- **WAF Bypass Techniques**: Advanced evasion payloads for modern web application firewalls
- **Real-time Analysis**: Live vulnerability detection with pattern matching

### 🛡️ **Enterprise Security Features**
- **User Authentication**: Secure multi-user environment with role-based access control
- **API Key Management**: Programmatic access with secure API key authentication
- **Test History**: Comprehensive audit trails and historical analysis
- **Session Management**: Secure session handling with Flask-Login integration

## 🏗️ Architecture Overview

```
SQL Injector v2.0 Architecture
├── Frontend (React + Tailwind CSS)
│   ├── Real-time Testing Interface
│   ├── Report Generation Interface
│   └── User Management System
│
├── Backend (Flask + SQLAlchemy)
│   ├── Authentication & Authorization
│   ├── API Endpoints & Route Handlers
│   ├── Database Models & ORM
│   └── Security & Input Validation
│
├── Report Generation System
│   ├── HTML Template Engine (Jinja2)
│   ├── PDF Generation (pdfkit)
│   └── Risk Assessment Engine
│
└── Data Management
    ├── SQLite Database (User Data)
    ├── CSV Payload Database
    └── Test Results Storage
```

## 📁 Project Structure

```
sql-injector-v2/
│
├── app/                          # Flask application
│   ├── __init__.py              # App factory and configuration
│   ├── models.py                # Database models (User, TestSession, APIKey)
│   ├── auth.py                  # Authentication routes and utilities
│   ├── routes.py                # Main API routes and endpoints
│   ├── injector.py              # Core SQL injection testing logic
│   ├── static/
│   │   └── css/
│   │       └── style.css        # Custom styling and animations
│   └── templates/
│       ├── index.html           # Main application interface
│       └── auth/
│           ├── login.html       # User login page
│           └── register.html    # User registration page
│
├── report_generator.py          # Report generation
├── payloads.py                  # Local payload database (18 categories)
├── run.py                       # Application entry point with CLI
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variables template
│
├── reports/                     # Generated reports
│   ├── html/                   # HTML reports
│   └── pdf/                    # PDF reports
│
└── README.md                    # This file
```

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.8+** (Python 3.9+ recommended)
- **pip** (Python package installer)
- **wkhtmltopdf** (for PDF generation)
- **Git** (for cloning the repository)

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/sql-injector-v2.git
cd sql-injector-v2
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install wkhtmltopdf for PDF generation
# On Ubuntu/Debian:
sudo apt-get install wkhtmltopdf

# On macOS:
brew install wkhtmltopdf

# On Windows:
# Download from: https://wkhtmltopdf.org/downloads.html
```

### Step 4: Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
nano .env
```

**Required Environment Variables:**

```env
# Flask Configuration
SECRET_KEY=your_super_secret_key_here
FLASK_DEBUG=False

# Database Configuration
DATABASE_URL=sqlite:///sqli_tester.db

# Security Settings
MAX_PAYLOAD_LENGTH=1000
REQUEST_TIMEOUT=10
MAX_CONCURRENT_TESTS=5

# Report Configuration
REPORTS_DIR=reports
ENABLE_PDF_REPORTS=True
```

### Step 5: Initialize Database

```bash
# Initialize the database and create default admin user
python run.py --init-db
```

This creates:
- Database tables
- Default admin user: `admin` / `admin123` (⚠️ Change immediately!)

### Step 6: Start the Application

```bash
# Start the web application
python run.py

# Or with custom configuration
python run.py --host 0.0.0.0 --port 8080 --debug
```

## 🚀 Usage Guide

### Web Interface

1. **Access the Application**
   ```
   http://localhost:5000
   ```

2. **Login with Default Credentials**
   - Username: `admin`
   - Password: `admin123`
   - ⚠️ **Change these immediately in production!**

3. **Configure Test Parameters**
   - Target URL: `https://example.com/page.php?id=1`
   - Parameter: `id`
   - Method: `GET` or `POST`
   - Custom Headers (optional)
   - Cookies (optional)

4. **Launch SQL Injection Test**
   - Click "Launch Injection Tests"
   - Monitor real-time progress
   - Review results

5. **Generate Reports**
   - Navigate to Test History
   - Click "HTML Report" or "PDF Report"
   - Download security reports

### Command Line Interface

```bash
# View all available options
python run.py --help

# Fetch payload statistics
python run.py --fetch-payloads

# Start with custom configuration
python run.py --host 127.0.0.1 --port 8080 --debug

# Initialize database
python run.py --init-db
```

### API Usage

#### Authentication
```bash
# Login and get session
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Create API key
curl -X POST http://localhost:5000/auth/api-keys \
  -H "Content-Type: application/json" \
  -b "session=your_session_cookie" \
  -d '{"key_name": "test-key"}'
```

#### SQL Injection Testing
```bash
# Run test with session authentication
curl -X POST http://localhost:5000/api/test-sqli \
  -H "Content-Type: application/json" \
  -b "session=your_session_cookie" \
  -d '{
    "target_url": "https://example.com/page.php?id=1",
    "parameter": "id",
    "method": "GET"
  }'

# Run test with API key
curl -X POST http://localhost:5000/api/test-sqli-public \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "target_url": "https://example.com/page.php?id=1",
    "parameter": "id",
    "method": "GET"
  }'
```

#### Report Generation
```bash
# Generate report
curl -X POST http://localhost:5000/api/generate-report \
  -H "Content-Type: application/json" \
  -b "session=your_session_cookie" \
  -d '{
    "session_id": 123,
    "format": "html"
  }'

# Download report
curl -X GET "http://localhost:5000/api/download-report/123?format=pdf" \
  -b "session=your_session_cookie" \
  -o security-report.pdf
```

## 📊 Reporting

### Report Features

#### Executive Summary
- Business impact analysis
- Risk level assessment (Low/Medium/High/Critical)
- Executive-friendly vulnerability overview
- Compliance implications

#### Technical Analysis
- Detailed vulnerability breakdown
- Payload analysis and categorization
- Response pattern analysis
- Attack vector identification

#### Risk Assessment
- CVSS-style scoring
- Business impact evaluation
- Exploitability assessment
- Remediation priority ranking

#### Recommendations
- Specific remediation steps
- Code examples for fixes
- Best practice guidelines
- Prevention strategies

### Report Formats

#### HTML Reports
- Interactive web-based reports
- Responsive design for all devices
- Embedded charts and visualizations
- Shareable via web links

#### PDF Reports
- Professional print-ready format
- Executive presentation quality
- Compliance documentation ready
- Secure distribution format

### Customizing Reports

```python
# Custom report generation
from report_generator import SQLIReportGenerator

generator = SQLIReportGenerator()
report = generator.generate_complete_report(
    test_results=your_test_results,
    user_info=user_data,
    format_type="pdf"
)
```

## 🔧 Configuration Options

### Application Settings

```python
# app/config.py
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Settings
    MAX_PAYLOAD_LENGTH = 1000
    REQUEST_TIMEOUT = 10
    MAX_CONCURRENT_TESTS = 5
    
    # Report Settings
    REPORTS_DIR = 'reports'
    ENABLE_PDF_REPORTS = True
```

### Payload Configuration

```python
# payloads.py customization
def get_custom_payloads():
    return [
        "' OR 1=1--",
        "admin' OR '1'='1",
        # Add your custom payloads
    ]
```

### Security Configuration

```python
# Security headers and validation
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block'
}

# Input validation rules
VALIDATION_RULES = {
    'max_url_length': 2048,
    'allowed_protocols': ['http', 'https'],
    'blocked_networks': ['127.0.0.1', '192.168.0.0/16']
}
```

## 🔒 Security Considerations

### Network Security
- **Internal Network Protection**: Automatically blocks testing of private networks
- **Rate Limiting**: Built-in delays to prevent target overload
- **Request Validation**: Comprehensive URL and parameter validation
- **Timeout Protection**: Configurable request timeouts

### Data Security
- **Password Hashing**: Werkzeug secure password hashing
- **Session Security**: Flask-Login secure session management
- **API Key Encryption**: Secure API key storage and validation
- **Input Sanitization**: Comprehensive input validation and sanitization

### Audit and Compliance
- **Test History**: Complete audit trails of all testing activities
- **User Tracking**: Detailed user activity logging
- **Report Generation**: Compliance-ready security reports
- **Access Control**: Role-based access control system

## 🐛 Troubleshooting

### Common Issues

#### 1. PDF Generation Fails
```bash
# Install wkhtmltopdf
sudo apt-get install wkhtmltopdf

# Check installation
which wkhtmltopdf

# Test PDF generation
python -c "import pdfkit; print('PDF generation available')"
```

#### 2. Database Issues
```bash
# Reset database
rm sqli_tester.db
python run.py --init-db

# Check database
sqlite3 sqli_tester.db ".tables"
```

### Performance Optimization

#### 1. Testing Performance
```python
# Adjust concurrent workers
MAX_WORKERS = 3  # Reduce for slower targets
REQUEST_TIMEOUT = 15  # Increase for slow responses
```

#### 2. Memory Usage
```python
# Monitor memory usage
import psutil
print(f"Memory usage: {psutil.Process().memory_info().rss / 1024 / 1024:.1f} MB")
```

## 📈 Advanced Usage

### Batch Testing

```python
# Test multiple targets
targets = [
    {'url': 'https://site1.com/page?id=1', 'param': 'id'},
    {'url': 'https://site2.com/search?q=test', 'param': 'q'},
]

for target in targets:
    results = test_target(target['url'], target['param'])
    generate_report(results)
```

### Custom Payload Development

```python
# Add custom payload categories
CUSTOM_PAYLOADS = {
    'nosql_injection': [
        "'; return true; //",
        "' || '1'=='1",
        "[$ne]=1"
    ],
    'xml_injection': [
        "<!--#exec cmd=\"ls\"-->",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>"
    ]
}
```

## 🤝 Contributing

We welcome contributions to improve SQL Injector v2.0! Please ensure all contributions follow ethical security research practices.

### Development Setup

```bash
# Clone development branch
git clone -b develop https://github.com/your-username/sql-injector-v2.git

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black app/ report_generator.py
flake8 app/ report_generator.py
```

### Contribution Guidelines

1. **Ethical Use**: All contributions must support authorized security testing only
2. **Code Quality**: Follow PEP 8 and include comprehensive tests
3. **Documentation**: Update documentation for new features
4. **Security**: Ensure all code follows security best practices

## 📄 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations.

## 🆘 Support

- **Documentation**: Check this README and inline code comments
- **Issues**: Report bugs via GitHub Issues
- **Security**: Report security issues privately to security@example.com
- **Community**: Join our Discord server for discussions

## 🙏 Acknowledgments

- **Dataset**: SQL injection dataset from Kaggle community
- **Security Community**: OWASP and security researchers worldwide

---

**Remember: Use this tool responsibly and only on systems you are authorized to test. Happy ethical hacking! 🛡️**


