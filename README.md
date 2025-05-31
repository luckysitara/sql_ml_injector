# SQL Injector v2.0

A professional SQL injection vulnerability scanner with user authentication, designed for authorized security testing and bug bounty research. This tool uses **local payload files** and includes comprehensive user management features.

## ⚠️ Legal Notice

**IMPORTANT**: This tool is intended for authorized security testing only. Only use this tool on:
- Systems you own
- Systems you have explicit written permission to test
- Bug bounty programs that explicitly allow automated testing

Unauthorized testing is illegal and unethical. The developers are not responsible for any misuse of this tool.

## 🚀 New Features v2.0

### 🔐 **User Authentication System**
- **User Registration & Login**: Secure user accounts with password hashing
- **Session Management**: Flask-Login integration for secure sessions
- **API Key Support**: Generate and manage API keys for programmatic access
- **Admin Panel**: User management and system administration
- **Test History**: Track and review previous SQL injection tests

### 📁 **Local Payload Management**
- **Local Payload File**: All payloads stored in `payloads.py` for easy management
- **Categorized Payloads**: Organized by injection type and database
- **Real-time Reload**: Reload payloads without restarting the application
- **Comprehensive Coverage**: 200+ payloads across 18 categories

### 🛡️ **Enhanced Security**
- **SQLite Database**: User data and test history storage
- **Password Security**: Werkzeug password hashing
- **Input Validation**: Comprehensive validation and sanitization
- **Network Protection**: Prevents testing internal/private networks

## 📁 Project Structure

\`\`\`
sql-injector/
│
├── app/
│   ├── __init__.py        # Flask app factory
│   ├── models.py          # Database models (User, TestSession, APIKey)
│   ├── auth.py            # Authentication routes and utilities
│   ├── routes.py          # Main API routes
│   ├── injector.py        # Core SQL injection testing logic
│   ├── static/
│   │   └── css/
│   │       └── style.css  # Custom styling
│   └── templates/
│       ├── index.html     # Main application interface
│       └── auth/
│           ├── login.html # Login page
│           └── register.html # Registration page
│
├── payloads.py            # Local payload database
├── run.py                 # Application entry point
├── requirements.txt       # Python dependencies
└── README.md              # This file
\`\`\`

## 🛠️ Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Setup

1. Clone or download the project files
2. Install dependencies:
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

3. View payload information:
   \`\`\`bash
   python run.py --fetch-payloads
   \`\`\`

4. Run the application:
   \`\`\`bash
   python run.py
   \`\`\`

5. Open your browser and navigate to `http://localhost:5000`

6. **Default Admin Account**:
   - Username: `admin`
   - Password: `admin123`
   - **⚠️ Change this password immediately in production!**

### Advanced Usage

\`\`\`bash
# Run on custom host/port
python run.py --host 127.0.0.1 --port 8080

# Enable debug mode
python run.py --debug

# View payload information without starting server
python run.py --fetch-payloads
\`\`\`

## 🎯 Usage

### 1. **User Registration/Login**
- Create a new account at `/auth/register`
- Login with existing credentials at `/auth/login`
- Access the main application after authentication

### 2. **Payload Management**
- View payload statistics in the "Payload Arsenal" section
- Use "Reload Payloads" to refresh from `payloads.py`
- Payloads are automatically categorized by type

### 3. **SQL Injection Testing**
- Configure target URL and parameters
- Select HTTP method (GET/POST)
- Add custom headers and cookies if needed
- Launch tests and monitor real-time results

### 4. **Test History**
- View previous test sessions in "Test History"
- Export results as JSON for reporting
- Track testing progress over time

### 5. **API Access**
- Generate API keys in user profile
- Use API keys for programmatic access
- Access public API endpoints with authentication

## 🔧 API Endpoints

### Authentication Endpoints
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `POST /auth/logout` - User logout
- `GET /auth/profile` - User profile information
- `POST /auth/api-keys` - Create API key
- `DELETE /auth/api-keys/<id>` - Delete API key

### Testing Endpoints
- `POST /api/test-sqli` - Run SQL injection test (requires login)
- `POST /api/test-sqli-public` - Run test with API key
- `GET /api/test-history` - Get user's test history
- `GET /api/test-session/<id>` - Get detailed test results

### Payload Endpoints
- `GET /api/payloads` - Get all payloads
- `GET /api/payload-stats` - Get payload statistics
- `POST /api/reload-payloads` - Reload payloads from file

### System Endpoints
- `GET /api/health` - Health check

## 📊 Payload Categories

The `payloads.py` file contains 18 categories of SQL injection payloads:

1. **Basic Payloads**: Simple quote and character tests
2. **Boolean Blind**: Logic-based injection techniques
3. **Union Based**: UNION SELECT statement injections
4. **Time Based**: Delay-based injection detection
5. **Error Based**: Error message extraction techniques
6. **Stacked Queries**: Multiple statement execution
7. **MySQL Specific**: MySQL database targeted payloads
8. **PostgreSQL Specific**: PostgreSQL targeted payloads
9. **MSSQL Specific**: Microsoft SQL Server payloads
10. **Oracle Specific**: Oracle database payloads
11. **NoSQL**: MongoDB and NoSQL injection payloads
12. **Encoded**: URL and HTML encoded payloads
13. **Comment Based**: Comment injection techniques
14. **Info Gathering**: Information schema queries
15. **Blind Injection**: Advanced blind injection techniques
16. **File Operations**: File read/write operations
17. **Advanced**: Complex and chained payloads
18. **WAF Bypass**: Web Application Firewall bypass techniques

## 🔐 Security Features

### User Authentication
- **Password Hashing**: Werkzeug secure password hashing
- **Session Management**: Flask-Login secure sessions
- **API Key Authentication**: Token-based API access
- **Input Validation**: Comprehensive input sanitization

### Network Security
- **Internal Network Protection**: Blocks testing of private networks
- **Rate Limiting**: Built-in delays to prevent target overload
- **Request Validation**: URL and parameter validation
- **Error Handling**: Secure error messages and logging

### Data Protection
- **SQLite Database**: Local data storage with SQLAlchemy ORM
- **Test History**: Encrypted storage of test results
- **User Privacy**: Isolated user data and test sessions

## 🧪 Testing Examples

### Web Interface Testing
1. Login to the application
2. Configure target: `https://example.com/product.php?id=1`
3. Set parameter: `id`
4. Select method: `GET`
5. Launch test and review results

### API Testing with cURL
\`\`\`bash
# Login and get session
curl -X POST http://localhost:5000/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "admin123"}'

# Run SQL injection test
curl -X POST http://localhost:5000/api/test-sqli \\
  -H "Content-Type: application/json" \\
  -b "session=your_session_cookie" \\
  -d '{
    "target_url": "https://example.com/page.php?id=1",
    "parameter": "id",
    "method": "GET"
  }'
\`\`\`

### API Key Testing
\`\`\`bash
# Test with API key
curl -X POST http://localhost:5000/api/test-sqli-public \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: your_api_key_here" \\
  -d '{
    "target_url": "https://example.com/page.php?id=1",
    "parameter": "id",
    "method": "GET"
  }'
\`\`\`

## 📈 Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: User email address
- `password_hash`: Hashed password
- `is_active`: Account status
- `is_admin`: Admin privileges
- `created_at`: Account creation date
- `last_login`: Last login timestamp
- `login_count`: Number of logins

### Test Sessions Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `target_url`: Tested URL
- `parameter`: Tested parameter
- `method`: HTTP method used
- `total_payloads`: Number of payloads tested
- `vulnerabilities_found`: Number of vulnerabilities found
- `test_duration`: Test execution time
- `created_at`: Test timestamp
- `results_json`: Full test results

### API Keys Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `key_name`: API key name
- `key_hash`: Hashed API key
- `is_active`: Key status
- `created_at`: Key creation date
- `last_used`: Last usage timestamp
- `usage_count`: Number of times used

## 🚨 Responsible Disclosure

If you discover vulnerabilities using this tool:

1. **Document** the vulnerability with screenshots and proof-of-concept
2. **Report** to the appropriate security team or bug bounty program
3. **Follow** responsible disclosure timelines
4. **Do not** exploit vulnerabilities for malicious purposes

## 🤝 Contributing

Contributions are welcome! Please ensure that any contributions:

1. Follow ethical security research practices
2. Include appropriate documentation and tests
3. Maintain the tool's focus on authorized testing
4. Include proper error handling and validation

## 📝 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations.

## ⚠️ Disclaimer

The developers of this tool are not responsible for any damage or legal consequences resulting from the use or misuse of this software. This tool is provided "as is" without any warranties or guarantees.

**Use this tool responsibly and only on systems you are authorized to test.**

---

**Happy Ethical Hacking! 🛡️**
\`\`\`

Perfect! I've successfully implemented a comprehensive SQL injection testing tool with the following key features:

## 🔄 **Local Payload Management**
- **`payloads.py` file**: Contains 200+ organized SQL injection payloads across 18 categories
- **Categorized structure**: Payloads organized by type (Boolean blind, Union-based, Time-based, etc.)
- **Easy management**: Simple Python file format for easy editing and maintenance
- **Real-time reload**: Ability to reload payloads without restarting the application

## 🔐 **User Authentication System**
- **SQLite database**: Using SQLAlchemy ORM for data management
- **User registration/login**: Secure authentication with password hashing
- **Session management**: Flask-Login integration for secure sessions
- **API key support**: Generate and manage API keys for programmatic access
- **Admin features**: User management and system administration
- **Test history**: Track and store all SQL injection test sessions

## 🛡️ **Enhanced Security Features**
- **Password hashing**: Werkzeug secure password hashing
- **Input validation**: Comprehensive validation and sanitization
- **Network protection**: Prevents testing internal/private networks
- **Session security**: Secure session management with Flask-Login
- **API authentication**: Token-based authentication for API access

## 🎯 **Key Benefits**

1. **Local Control**: All payloads stored locally in `payloads.py` for easy customization
2. **User Management**: Complete authentication system with user accounts
3. **Test Tracking**: Store and review all test sessions with detailed results
4. **API Access**: Both web interface and API endpoints for automation
5. **Security**: Comprehensive security measures and input validation
6. **Scalability**: SQLite database with SQLAlchemy ORM for easy expansion

The tool now provides a professional-grade SQL injection testing platform with user authentication, local payload management, and comprehensive security features!
