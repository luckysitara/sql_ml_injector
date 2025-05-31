"""
Flask routes and API endpoints for the SQL injection testing tool.
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.injector import SQLInjectionTester
from app.models import TestSession, db
from app.auth import api_key_required
from urllib.parse import urlparse
import logging
import json
import time
from ml_model import SQLInjectionMLModel
from report_generator import SQLIReportGenerator
import tempfile
import os

# Create blueprint
main = Blueprint('main', __name__)

# Initialize the SQL injection tester
tester = SQLInjectionTester()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@main.route('/')
def index():
    """Serve the main application page"""
    return render_template('index.html')

@main.route('/api/test-sqli', methods=['POST'])
@login_required
def test_sqli():
    """
    API endpoint to run SQL injection tests against a target.
    Requires user authentication.
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        target_url = data.get('target_url')
        parameter = data.get('parameter')
        method = data.get('method', 'GET')
        custom_headers = data.get('custom_headers', '')
        cookies = data.get('cookies', '')
        
        if not target_url or not parameter:
            return jsonify({'error': 'Target URL and parameter are required'}), 400
        
        # Validate URL format
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return jsonify({'error': 'Invalid URL format'}), 400
        except Exception:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Security check - prevent testing internal networks
        if _is_internal_network(parsed.netloc):
            return jsonify({'error': 'Testing internal/private networks is not allowed'}), 403
        
        # Validate method
        if method.upper() not in ['GET', 'POST']:
            return jsonify({'error': 'Method must be GET or POST'}), 400
        
        # Log the test request
        logger.info(f"User {current_user.username} starting SQL injection test for {target_url} parameter '{parameter}'")
        
        # Record start time
        start_time = time.time()
        
        # Run the SQL injection test
        results = tester.test_target(
            target_url=target_url,
            parameter=parameter,
            method=method,
            custom_headers=custom_headers,
            cookies=cookies
        )
        
        # Calculate test duration
        test_duration = time.time() - start_time
        
        # Save test session to database
        try:
            test_session = TestSession(
                user_id=current_user.id,
                target_url=target_url,
                parameter=parameter,
                method=method,
                total_payloads=results['total_payloads'],
                vulnerabilities_found=results['vulnerabilities_found'],
                test_duration=test_duration,
                results_json=json.dumps(results)
            )
            db.session.add(test_session)
            db.session.commit()
            
            results['session_id'] = test_session.id
            
        except Exception as e:
            logger.error(f"Error saving test session: {str(e)}")
            # Continue without saving session
        
        # Log results summary
        logger.info(f"Test completed for user {current_user.username}: {results['vulnerabilities_found']}/{results['total_payloads']} vulnerabilities found")
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in SQL injection test: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@main.route('/api/test-sqli-public', methods=['POST'])
@api_key_required
def test_sqli_public():
    """
    Public API endpoint for SQL injection testing using API key authentication.
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        target_url = data.get('target_url')
        parameter = data.get('parameter')
        method = data.get('method', 'GET')
        custom_headers = data.get('custom_headers', '')
        cookies = data.get('cookies', '')
        
        if not target_url or not parameter:
            return jsonify({'error': 'Target URL and parameter are required'}), 400
        
        # Validate URL format
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return jsonify({'error': 'Invalid URL format'}), 400
        except Exception:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Security check - prevent testing internal networks
        if _is_internal_network(parsed.netloc):
            return jsonify({'error': 'Testing internal/private networks is not allowed'}), 403
        
        # Validate method
        if method.upper() not in ['GET', 'POST']:
            return jsonify({'error': 'Method must be GET or POST'}), 400
        
        # Log the test request
        logger.info(f"API key user {request.current_user.username} starting SQL injection test for {target_url}")
        
        # Record start time
        start_time = time.time()
        
        # Run the SQL injection test
        results = tester.test_target(
            target_url=target_url,
            parameter=parameter,
            method=method,
            custom_headers=custom_headers,
            cookies=cookies
        )
        
        # Calculate test duration
        test_duration = time.time() - start_time
        
        # Save test session to database
        try:
            test_session = TestSession(
                user_id=request.current_user.id,
                target_url=target_url,
                parameter=parameter,
                method=method,
                total_payloads=results['total_payloads'],
                vulnerabilities_found=results['vulnerabilities_found'],
                test_duration=test_duration,
                results_json=json.dumps(results)
            )
            db.session.add(test_session)
            db.session.commit()
            
            results['session_id'] = test_session.id
            
        except Exception as e:
            logger.error(f"Error saving test session: {str(e)}")
            # Continue without saving session
        
        # Log results summary
        logger.info(f"API test completed: {results['vulnerabilities_found']}/{results['total_payloads']} vulnerabilities found")
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in SQL injection test: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@main.route('/api/payloads', methods=['GET'])
def get_payloads():
    """
    API endpoint to retrieve the list of available SQL injection payloads.
    """
    try:
        payloads = tester.get_payloads()
        return jsonify({
            'payloads': payloads,
            'total_count': len(payloads)
        })
    except Exception as e:
        logger.error(f"Error retrieving payloads: {str(e)}")
        return jsonify({'error': f'Failed to retrieve payloads: {str(e)}'}), 500

@main.route('/api/payload-stats', methods=['GET'])
def get_payload_stats():
    """
    API endpoint to get payload statistics and categories.
    """
    try:
        stats = tester.get_payload_statistics()
        categories = tester.get_payload_categories()
        
        # Get sample payloads from each category
        sample_payloads = {}
        for category_name, category_payloads in categories.items():
            sample_payloads[category_name] = category_payloads[:3]  # First 3 from each category
        
        return jsonify({
            'total_payloads': stats['total_payloads'],
            'categories': stats['categories'],
            'category_count': stats['category_count'],
            'sample_payloads': sample_payloads
        })
        
    except Exception as e:
        logger.error(f"Error getting payload stats: {str(e)}")
        return jsonify({'error': f'Failed to get payload statistics: {str(e)}'}), 500

@main.route('/api/reload-payloads', methods=['POST'])
@login_required
def reload_payloads():
    """
    API endpoint to reload payloads from CSV or local file.
    """
    try:
        # Force reload from CSV
        logger.info(f"User {current_user.username} requesting payload reload...")
        
        # Clear any cached payloads and force fresh load
        tester.payloads = []
        tester.payloads = tester._load_payloads()
        
        if tester.payloads:
            payload_count = len(tester.payloads)
            source = 'CSV dataset' if payload_count > 1000 else 'Local file'
            
            logger.info(f"User {current_user.username} reloaded payloads successfully: {payload_count} payloads from {source}")
            
            return jsonify({
                'success': True,
                'message': f'Payloads reloaded successfully from {source}',
                'payload_count': payload_count,
                'source': source,
                'csv_loaded': payload_count > 1000
            })
        else:
            return jsonify({'error': 'Failed to reload payloads - no payloads found'}), 500
        
    except Exception as e:
        logger.error(f"Error reloading payloads: {e}")
        return jsonify({'error': f'Failed to reload payloads: {str(e)}'}), 500

@main.route('/api/test-history')
@login_required
def get_test_history():
    """
    API endpoint to get user's test history.
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Limit per_page to prevent abuse
        per_page = min(per_page, 100)
        
        test_sessions = TestSession.query.filter_by(user_id=current_user.id)\
            .order_by(TestSession.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'test_sessions': [session.to_dict() for session in test_sessions.items],
            'total': test_sessions.total,
            'pages': test_sessions.pages,
            'current_page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        logger.error(f"Error getting test history: {str(e)}")
        return jsonify({'error': f'Failed to get test history: {str(e)}'}), 500

@main.route('/api/test-session/<int:session_id>')
@login_required
def get_test_session(session_id):
    """
    API endpoint to get detailed test session results.
    """
    try:
        test_session = TestSession.query.filter_by(
            id=session_id, 
            user_id=current_user.id
        ).first()
        
        if not test_session:
            return jsonify({'error': 'Test session not found'}), 404
        
        session_data = test_session.to_dict()
        
        # Include full results if available
        if test_session.results_json:
            try:
                session_data['results'] = json.loads(test_session.results_json)
            except json.JSONDecodeError:
                logger.error(f"Error parsing results JSON for session {session_id}")
        
        return jsonify(session_data)
        
    except Exception as e:
        logger.error(f"Error getting test session: {str(e)}")
        return jsonify({'error': f'Failed to get test session: {str(e)}'}), 500

@main.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'SQL Injection Testing Tool',
        'payload_count': len(tester.get_payloads()),
        'version': '2.0.0'
    })

@main.route('/api/train-model', methods=['POST'])
@login_required
def train_model():
    """Train ML model with uploaded dataset"""
    try:
        if 'dataset' not in request.files:
            return jsonify({'error': 'No dataset file provided'}), 400
        
        file = request.files['dataset']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv', delete=False) as tmp_file:
            file.save(tmp_file.name)
            
            # Train model
            ml_model = SQLInjectionMLModel()
            results = ml_model.train_models(tmp_file.name)
            
            # Clean up temporary file
            os.unlink(tmp_file.name)
            
            logger.info(f"User {current_user.username} trained ML model successfully")
            
            return jsonify({
                'success': True,
                'message': 'Model trained successfully',
                'results': results
            })
            
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        return jsonify({'error': f'Failed to train model: {str(e)}'}), 500

@main.route('/api/model-info')
@login_required
def get_model_info():
    """Get ML model information"""
    try:
        ml_model = SQLInjectionMLModel()
        info = ml_model.get_model_info()
        return jsonify(info)
    except Exception as e:
        logger.error(f"Error getting model info: {str(e)}")
        return jsonify({'error': str(e)}), 500

@main.route('/api/generate-report', methods=['POST'])
@login_required
def generate_report():
    """Generate AI-powered security report"""
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        format_type = data.get('format', 'html')
        
        if not session_id:
            return jsonify({'error': 'Session ID required'}), 400
        
        # Get test session
        test_session = TestSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not test_session:
            return jsonify({'error': 'Test session not found'}), 404
        
        # Parse test results
        test_results = json.loads(test_session.results_json) if test_session.results_json else {}
        
        # Add session metadata
        test_results.update({
            'target_url': test_session.target_url,
            'parameter': test_session.parameter,
            'method': test_session.method,
            'total_payloads': test_session.total_payloads,
            'vulnerabilities_found': test_session.vulnerabilities_found
        })
        
        # Generate report
        generator = SQLIReportGenerator()
        report = generator.generate_complete_report(
            test_results,
            user_info=current_user.to_dict(),
            format_type=format_type
        )
        
        logger.info(f"User {current_user.username} generated {format_type} report for session {session_id}")
        
        return jsonify({
            'success': True,
            'report': report
        })
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

@main.route('/api/download-report/<int:session_id>')
@login_required
def download_report(session_id):
    """Download report as file"""
    try:
        format_type = request.args.get('format', 'html')
        
        # Get test session
        test_session = TestSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not test_session:
            return jsonify({'error': 'Test session not found'}), 404
        
        # Parse test results
        test_results = json.loads(test_session.results_json) if test_session.results_json else {}
        test_results.update({
            'target_url': test_session.target_url,
            'parameter': test_session.parameter,
            'method': test_session.method,
            'total_payloads': test_session.total_payloads,
            'vulnerabilities_found': test_session.vulnerabilities_found
        })
        
        # Generate report
        generator = SQLIReportGenerator()
        report = generator.generate_complete_report(
            test_results,
            user_info=current_user.to_dict(),
            format_type=format_type
        )
        
        if format_type == 'pdf':
            if 'pdf_content' in report:
                from flask import Response
                import base64
                
                pdf_data = base64.b64decode(report['pdf_content'])
                filename = f"sqli-report-{session_id}-{int(time.time())}.pdf"
                
                return Response(
                    pdf_data,
                    mimetype='application/pdf',
                    headers={'Content-Disposition': f'attachment; filename={filename}'}
                )
            else:
                return jsonify({'error': 'PDF generation failed'}), 500
        else:
            from flask import Response
            filename = f"sqli-report-{session_id}-{int(time.time())}.html"
            
            return Response(
                report['html_content'],
                mimetype='text/html',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
            
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        return jsonify({'error': f'Failed to download report: {str(e)}'}), 500

def _is_internal_network(hostname):
    """
    Check if the hostname/IP is part of internal/private networks.
    Returns True if the target is internal and should be blocked.
    """
    import re
    
    # Patterns for internal/private networks
    internal_patterns = [
        r'^localhost$',
        r'^127\.',
        r'^192\.168\.',
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^0\.0\.0\.0$',
        r'^::1$',
        r'^fe80:',
        r'^fc00:',
        r'^fd00:',
    ]
    
    for pattern in internal_patterns:
        if re.match(pattern, hostname, re.IGNORECASE):
            return True
    
    return False

@main.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@main.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500
