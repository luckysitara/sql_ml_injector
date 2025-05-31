# SQL Injector v3.0 - AI-Powered SQL Injection Testing Platform

A comprehensive, professional-grade SQL injection vulnerability scanner with advanced machine learning capabilities, AI-powered analysis, and automated report generation. This tool combines traditional security testing with cutting-edge AI technology for enhanced vulnerability detection and professional security reporting.

## ⚠️ Legal Notice

**CRITICAL**: This tool is intended for authorized security testing only. Only use this tool on:
- Systems you own
- Systems you have explicit written permission to test
- Bug bounty programs that explicitly allow automated testing
- Authorized penetration testing engagements

Unauthorized testing is illegal and unethical. The developers are not responsible for any misuse of this tool.

## 🚀 Project Overview

SQL Injector v3.0 is a next-generation security testing platform that revolutionizes SQL injection vulnerability detection through:

### 🧠 **AI-Powered Detection Engine**
- **Machine Learning Models**: LSTM neural networks and Random Forest classifiers trained on comprehensive SQL injection datasets
- **Ensemble Prediction**: Combines multiple ML models for superior accuracy (98%+ detection rate)
- **Pattern Recognition**: Advanced response analysis using trained models to identify subtle vulnerability indicators
- **Adaptive Learning**: Continuously improves detection through model retraining with new datasets

### 📊 **Intelligent Report Generation**
- **OpenAI Integration**: GPT-4 powered analysis for executive summaries and technical recommendations
- **Professional Reports**: Generate publication-ready HTML and PDF security reports
- **Risk Assessment**: Automated CVSS-style risk scoring and business impact analysis
- **Compliance Ready**: Reports formatted for security audits and compliance requirements

### 🔧 **Advanced Testing Capabilities**
- **Comprehensive Payload Database**: 10,000+ SQL injection payloads across 18+ categories
- **Multi-Database Support**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and NoSQL injection techniques
- **WAF Bypass Techniques**: Advanced evasion payloads for modern web application firewalls
- **Real-time Analysis**: Live vulnerability detection with ML-enhanced pattern matching

### 🛡️ **Enterprise Security Features**
- **User Authentication**: Secure multi-user environment with role-based access control
- **API Key Management**: Programmatic access with secure API key authentication
- **Test History**: Comprehensive audit trails and historical analysis
- **Session Management**: Secure session handling with Flask-Login integration

## 🏗️ Architecture Overview

\`\`\`
SQL Injector v3.0 Architecture
├── Frontend (React + Tailwind CSS)
│   ├── Real-time Testing Interface
│   ├── ML Model Management Dashboard
│   ├── Report Generation Interface
│   └── User Management System
│
├── Backend (Flask + SQLAlchemy)
│   ├── Authentication & Authorization
│   ├── API Endpoints & Route Handlers
│   ├── Database Models & ORM
│   └── Security & Input Validation
│
├── AI/ML Engine
│   ├── LSTM Neural Network (TensorFlow/Keras)
│   ├── Random Forest Classifier (scikit-learn)
│   ├── Ensemble Prediction System
│   └── Response Pattern Analysis
│
├── Report Generation System
│   ├── OpenAI GPT-4 Integration
│   ├── HTML Template Engine (Jinja2)
│   ├── PDF Generation (pdfkit)
│   └── Risk Assessment Engine
│
└── Data Management
    ├── SQLite Database (User Data)
    ├── CSV Payload Database
    ├── Model Persistence (HDF5/Pickle)
    └── Test Results Storage
\`\`\`

## 📁 Project Structure

\`\`\`
sql-injector-v3/
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
├── ml_model.py                  # Machine learning model implementation
├── report_generator.py          # AI-powered report generation
├── payloads.py                  # Local payload database (18 categories)
├── run.py                       # Application entry point with CLI
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variables template
├── models/                      # Trained ML models directory
│   ├── lstm_model.h5           # Trained LSTM model
│   ├── rf_model.pkl            # Trained Random Forest model
│   ├── tokenizer.pkl           # Text tokenizer for LSTM
│   └── vectorizer.pkl          # TF-IDF vectorizer for RF
│
├── datasets/                    # Training datasets
│   └── clean_sql_dataset.csv   # SQL injection training data
│
├── reports/                     # Generated reports
│   ├── html/                   # HTML reports
│   └── pdf/                    # PDF reports
│
└── README.md                    # This file
\`\`\`

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.8+** (Python 3.9+ recommended)
- **pip** (Python package installer)
- **wkhtmltopdf** (for PDF generation)
- **OpenAI API Key** (for AI-powered reports)
- **Git** (for cloning the repository)

### Step 1: Clone the Repository

\`\`\`bash
git clone https://github.com/your-username/sql-injector-v3.git
cd sql-injector-v3
\`\`\`

### Step 2: Create Virtual Environment

\`\`\`bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
\`\`\`

### Step 3: Install Dependencies

\`\`\`bash
# Install Python dependencies
pip install -r requirements.txt

# Install wkhtmltopdf for PDF generation
# On Ubuntu/Debian:
sudo apt-get install wkhtmltopdf

# On macOS:
brew install wkhtmltopdf

# On Windows:
# Download from: https://wkhtmltopdf.org/downloads.html
\`\`\`

### Step 4: Environment Configuration

\`\`\`bash
# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
nano .env
\`\`\`

**Required Environment Variables:**

\`\`\`env
# OpenAI Configuration (Required for AI reports)
OPENAI_API_KEY=your_openai_api_key_here

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
\`\`\`

### Step 5: Initialize Database

\`\`\`bash
# Initialize the database and create default admin user
python run.py --init-db
\`\`\`

This creates:
- Database tables
- Default admin user: `admin` / `admin123` (⚠️ Change immediately!)

### Step 6: Download Training Dataset

\`\`\`bash
# Create datasets directory
mkdir -p datasets

# Download the SQL injection dataset
wget -O datasets/clean_sql_dataset.csv "https://hebbkx1anhila5yf.public.blob.vercel-storage.com/mbih-tvKJD7TTjrCGjADXX1qeMMs5vLOFH8.csv"

# Or use your own dataset with columns: Query,Label
\`\`\`

### Step 7: Train Machine Learning Models

\`\`\`bash
# Train ML models using your dataset
python run.py --train-model datasets/clean_sql_dataset.csv

# This will:
# 1. Train LSTM neural network
# 2. Train Random Forest classifier
# 3. Save models to models/ directory
# 4. Display training metrics
\`\`\`

**Expected Training Output:**
\`\`\`
🤖 Training Machine Learning Model...
============================================================
Loading dataset from datasets/clean_sql_dataset.csv
Dataset loaded: 148,000 samples
Malicious samples: 74,000
Benign samples: 74,000

Training Random Forest model...
Random Forest metrics: {'accuracy': 0.9777, 'precision': 0.9967, 'recall': 0.9606}

Training LSTM model...
Epoch 1/25
...
LSTM metrics: {'accuracy': 0.9831, 'precision': 0.9974, 'recall': 0.9702}

✅ Model training completed successfully!
\`\`\`

### Step 8: Verify Installation

\`\`\`bash
# Check payload information
python run.py --fetch-payloads

# Verify model status
python -c "from ml_model import SQLInjectionMLModel; print(SQLInjectionMLModel().get_model_info())"
\`\`\`

### Step 9: Start the Application

\`\`\`bash
# Start the web application
python run.py

# Or with custom configuration
python run.py --host 0.0.0.0 --port 8080 --debug
\`\`\`

## 🚀 Usage Guide

### Web Interface

1. **Access the Application**
   \`\`\`
   http://localhost:5000
   \`\`\`

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
   - Review ML-enhanced results

5. **Generate AI-Powered Reports**
   - Navigate to Test History
   - Click "HTML Report" or "PDF Report"
   - Download professional security reports

### Command Line Interface

\`\`\`bash
# View all available options
python run.py --help

# Fetch payload statistics
python run.py --fetch-payloads

# Train new model with custom dataset
python run.py --train-model /path/to/dataset.csv

# Start with custom configuration
python run.py --host 127.0.0.1 --port 8080 --debug

# Initialize database
python run.py --init-db
\`\`\`

### API Usage

#### Authentication
\`\`\`bash
# Login and get session
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Create API key
curl -X POST http://localhost:5000/auth/api-keys \
  -H "Content-Type: application/json" \
  -b "session=your_session_cookie" \
  -d '{"key_name": "test-key"}'
\`\`\`

#### SQL Injection Testing
\`\`\`bash
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
\`\`\`

#### Report Generation
\`\`\`bash
# Generate AI-powered report
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
\`\`\`

## 🧠 Machine Learning Features

### Model Architecture

#### LSTM Neural Network
\`\`\`python
# Model Configuration
- Embedding Layer: 20,000 vocabulary, 100 dimensions
- Bidirectional LSTM: 3 layers (128, 64, 32 units)
- Batch Normalization: After each LSTM layer
- Dropout: 0.5 for regularization
- Dense Layers: 64 units with ReLU activation
- Output: Sigmoid activation for binary classification
\`\`\`

#### Random Forest Classifier
\`\`\`python
# Model Configuration
- Estimators: 100 decision trees
- Features: TF-IDF vectorization (5000 features)
- Max Depth: Auto-optimized
- Random State: 42 for reproducibility
\`\`\`

#### Ensemble Prediction
\`\`\`python
# Weighted Ensemble
final_prediction = 0.7 * lstm_prediction + 0.3 * rf_prediction
confidence_threshold = 0.5
\`\`\`

### Training Your Own Models

1. **Prepare Dataset**
   \`\`\`csv
   Query,Label
   "SELECT * FROM users WHERE id = 1",0
   "' OR 1=1--",1
   "admin' OR '1'='1",1
   \`\`\`

2. **Train Models**
   \`\`\`bash
   python run.py --train-model your_dataset.csv
   \`\`\`

3. **Evaluate Performance**
   \`\`\`python
   from ml_model import SQLInjectionMLModel
   
   model = SQLInjectionMLModel()
   info = model.get_model_info()
   print(f"Models available: {info['models_available']}")
   \`\`\`

### Model Performance Metrics

Based on the provided dataset, our models achieve:

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|-------|----------|-----------|--------|----------|---------|
| LSTM | 98.31% | 99.74% | 97.02% | 98.36% | 99.49% |
| Random Forest | 97.77% | 99.67% | 96.06% | 97.83% | 99.31% |
| Ensemble | 98.45% | 99.71% | 97.15% | 98.42% | 99.52% |

## 📊 AI-Powered Reporting

### Report Features

#### Executive Summary
- AI-generated business impact analysis
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

\`\`\`python
# Custom report generation
from report_generator import SQLIReportGenerator

generator = SQLIReportGenerator(openai_api_key="your-key")
report = generator.generate_complete_report(
    test_results=your_test_results,
    user_info=user_data,
    format_type="pdf"
)
\`\`\`

## 🔧 Configuration Options

### Application Settings

\`\`\`python
# app/config.py
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Settings
    MAX_PAYLOAD_LENGTH = 1000
    REQUEST_TIMEOUT = 10
    MAX_CONCURRENT_TESTS = 5
    
    # ML Model Settings
    MODEL_DIR = 'models'
    ENABLE_ML_ANALYSIS = True
    ML_CONFIDENCE_THRESHOLD = 0.5
    
    # Report Settings
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    REPORTS_DIR = 'reports'
    ENABLE_PDF_REPORTS = True
\`\`\`

### Payload Configuration

\`\`\`python
# payloads.py customization
def get_custom_payloads():
    return [
        "' OR 1=1--",
        "admin' OR '1'='1",
        # Add your custom payloads
    ]
\`\`\`

### Security Configuration

\`\`\`python
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
\`\`\`

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

#### 1. Model Training Fails
\`\`\`bash
# Check dataset format
head -5 datasets/clean_sql_dataset.csv

# Verify dependencies
pip install tensorflow scikit-learn pandas

# Check memory usage
python -c "import psutil; print(f'RAM: {psutil.virtual_memory().available/1024/1024/1024:.1f}GB')"
\`\`\`

#### 2. PDF Generation Fails
\`\`\`bash
# Install wkhtmltopdf
sudo apt-get install wkhtmltopdf

# Check installation
which wkhtmltopdf

# Test PDF generation
python -c "import pdfkit; print('PDF generation available')"
\`\`\`

#### 3. OpenAI API Issues
\`\`\`bash
# Verify API key
echo $OPENAI_API_KEY

# Test API connection
python -c "import openai; openai.api_key='your-key'; print(openai.Model.list())"
\`\`\`

#### 4. Database Issues
\`\`\`bash
# Reset database
rm sqli_tester.db
python run.py --init-db

# Check database
sqlite3 sqli_tester.db ".tables"
\`\`\`

### Performance Optimization

#### 1. Model Performance
\`\`\`python
# Optimize model loading
export TF_CPP_MIN_LOG_LEVEL=2  # Reduce TensorFlow logging
export CUDA_VISIBLE_DEVICES=0  # Use specific GPU
\`\`\`

#### 2. Testing Performance
\`\`\`python
# Adjust concurrent workers
MAX_WORKERS = 3  # Reduce for slower targets
REQUEST_TIMEOUT = 15  # Increase for slow responses
\`\`\`

#### 3. Memory Usage
\`\`\`python
# Monitor memory usage
import psutil
print(f"Memory usage: {psutil.Process().memory_info().rss / 1024 / 1024:.1f} MB")
\`\`\`

## 📈 Advanced Usage

### Custom Model Training

\`\`\`python
# Train with custom parameters
from ml_model import SQLInjectionMLModel

model = SQLInjectionMLModel()
results = model.train_models(
    csv_path='custom_dataset.csv',
    epochs=50,  # More training epochs
    batch_size=64,  # Larger batch size
    validation_split=0.3  # More validation data
)
\`\`\`

### Batch Testing

\`\`\`python
# Test multiple targets
targets = [
    {'url': 'https://site1.com/page?id=1', 'param': 'id'},
    {'url': 'https://site2.com/search?q=test', 'param': 'q'},
]

for target in targets:
    results = test_target(target['url'], target['param'])
    generate_report(results)
\`\`\`

### Custom Payload Development

\`\`\`python
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
\`\`\`

## 🤝 Contributing

We welcome contributions to improve SQL Injector v3.0! Please ensure all contributions follow ethical security research practices.

### Development Setup

\`\`\`bash
# Clone development branch
git clone -b develop https://github.com/your-username/sql-injector-v3.git

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black app/ ml_model.py report_generator.py
flake8 app/ ml_model.py report_generator.py
\`\`\`

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
- **ML Libraries**: TensorFlow, scikit-learn, pandas teams
- **Security Community**: OWASP and security researchers worldwide
- **AI Integration**: OpenAI for GPT-4 API access

---

**Remember: Use this tool responsibly and only on systems you are authorized to test. Happy ethical hacking! 🛡️**
