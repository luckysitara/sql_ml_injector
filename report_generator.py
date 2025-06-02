"""
Report generator for SQL injection testing results.
Generates HTML and PDF reports with vulnerability analysis.
"""

import os
import json
import logging
import time
import datetime
from urllib.parse import urlparse
import base64

# Setup logging
logger = logging.getLogger(__name__)

class SQLIReportGenerator:
    """
    Generates comprehensive security reports for SQL injection tests.
    """
    
    def __init__(self, report_dir='reports'):
        """
        Initialize the report generator.
        
        Args:
            report_dir: Directory to save reports
        """
        self.report_dir = report_dir
        
        # Create reports directory if it doesn't exist
        os.makedirs(report_dir, exist_ok=True)
    
    def generate_complete_report(self, test_results, user_info=None, format_type='html'):
        """
        Generate a complete security report for SQL injection test results.
        
        Args:
            test_results: Dictionary containing test results
            user_info: Dictionary containing user information
            format_type: Report format ('html' or 'pdf')
            
        Returns:
            dict: Report content and metadata
        """
        try:
            # Generate HTML report
            html_content = self._generate_html_report(test_results, user_info)
            
            # Save HTML report
            timestamp = int(time.time())
            target_host = urlparse(test_results.get('target_url', '')).netloc
            html_filename = f"sqli_report_{target_host}_{timestamp}.html"
            html_path = os.path.join(self.report_dir, html_filename)
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report saved to {html_path}")
            
            # Generate PDF if requested
            pdf_content = None
            pdf_path = None
            
            if format_type == 'pdf':
                try:
                    pdf_content, pdf_path = self._generate_pdf_report(html_content, html_path)
                    logger.info(f"PDF report saved to {pdf_path}")
                except Exception as e:
                    logger.error(f"Error generating PDF report: {e}")
                    # Fall back to HTML if PDF generation fails
                    format_type = 'html'
            
            return {
                'format': format_type,
                'html_content': html_content,
                'html_path': html_path,
                'pdf_content': base64.b64encode(pdf_content).decode('utf-8') if pdf_content else None,
                'pdf_path': pdf_path,
                'timestamp': timestamp,
                'target': test_results.get('target_url', ''),
                'vulnerabilities_found': test_results.get('vulnerabilities_found', 0),
                'total_payloads': test_results.get('total_payloads', 0)
            }
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {
                'error': str(e),
                'format': 'html',
                'html_content': f"<h1>Error Generating Report</h1><p>{str(e)}</p>",
                'timestamp': int(time.time())
            }
    
    def _generate_html_report(self, test_results, user_info=None):
        """
        Generate HTML report for SQL injection test results.
        
        Args:
            test_results: Dictionary containing test results
            user_info: Dictionary containing user information
            
        Returns:
            str: HTML report content
        """
        try:
            # Extract test information
            target_url = test_results.get('target_url', 'Unknown')
            parameter = test_results.get('parameter', 'Unknown')
            vulnerabilities_found = test_results.get('vulnerabilities_found', 0)
            total_payloads = test_results.get('total_payloads', 0)
            results = test_results.get('results', [])
            
            # Calculate vulnerability percentage
            vulnerability_percentage = (vulnerabilities_found / total_payloads * 100) if total_payloads > 0 else 0
            
            # Determine risk level
            risk_level = 'Critical' if vulnerability_percentage > 10 else 'High' if vulnerability_percentage > 5 else 'Medium' if vulnerability_percentage > 1 else 'Low'
            risk_color = '#d9534f' if risk_level == 'Critical' else '#f0ad4e' if risk_level == 'High' else '#5bc0de' if risk_level == 'Medium' else '#5cb85c'
            
            # Get current date and time
            current_datetime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Start building HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>SQL Injection Security Report - {target_url}</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        margin: 0;
                        padding: 0;
                        background-color: #f9f9f9;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #fff;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }}
                    .header {{
                        background-color: #343a40;
                        color: white;
                        padding: 20px;
                        margin-bottom: 20px;
                        border-radius: 5px;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 24px;
                    }}
                    .header p {{
                        margin: 5px 0 0;
                        opacity: 0.8;
                    }}
                    .summary {{
                        background-color: #f8f9fa;
                        padding: 20px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                    }}
                    .risk-badge {{
                        display: inline-block;
                        padding: 5px 10px;
                        border-radius: 3px;
                        color: white;
                        background-color: {risk_color};
                        font-weight: bold;
                    }}
                    .stats {{
                        display: flex;
                        flex-wrap: wrap;
                        margin: 0 -10px;
                    }}
                    .stat-box {{
                        flex: 1;
                        min-width: 200px;
                        margin: 10px;
                        padding: 15px;
                        background-color: #fff;
                        border-radius: 5px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        text-align: center;
                    }}
                    .stat-box h3 {{
                        margin-top: 0;
                        color: #6c757d;
                        font-size: 14px;
                        text-transform: uppercase;
                    }}
                    .stat-box p {{
                        margin: 0;
                        font-size: 24px;
                        font-weight: bold;
                    }}
                    .progress {{
                        height: 20px;
                        background-color: #e9ecef;
                        border-radius: 5px;
                        margin: 10px 0;
                        overflow: hidden;
                    }}
                    .progress-bar {{
                        height: 100%;
                        background-color: {risk_color};
                        width: {vulnerability_percentage}%;
                        text-align: center;
                        color: white;
                        line-height: 20px;
                        font-size: 12px;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin: 20px 0;
                    }}
                    th, td {{
                        padding: 12px 15px;
                        text-align: left;
                        border-bottom: 1px solid #e9ecef;
                    }}
                    th {{
                        background-color: #f8f9fa;
                        font-weight: bold;
                    }}
                    tr:hover {{
                        background-color: #f8f9fa;
                    }}
                    .vulnerable {{
                        color: #d9534f;
                        font-weight: bold;
                    }}
                    .safe {{
                        color: #5cb85c;
                    }}
                    .section {{
                        margin-bottom: 30px;
                    }}
                    .section h2 {{
                        border-bottom: 2px solid #f8f9fa;
                        padding-bottom: 10px;
                        color: #343a40;
                    }}
                    .footer {{
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #e9ecef;
                        text-align: center;
                        font-size: 12px;
                        color: #6c757d;
                    }}
                    .recommendations {{
                        background-color: #f8f9fa;
                        padding: 20px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                    }}
                    .recommendations ul {{
                        padding-left: 20px;
                    }}
                    .recommendations li {{
                        margin-bottom: 10px;
                    }}
                    .code {{
                        font-family: monospace;
                        background-color: #f8f9fa;
                        padding: 2px 4px;
                        border-radius: 3px;
                    }}
                    .details-toggle {{
                        cursor: pointer;
                        color: #007bff;
                        text-decoration: underline;
                    }}
                    .details-content {{
                        display: none;
                        padding: 10px;
                        background-color: #f8f9fa;
                        border-radius: 5px;
                        margin-top: 10px;
                    }}
                </style>
                <script>
                    function toggleDetails(id) {{
                        var content = document.getElementById(id);
                        if (content.style.display === "block") {{
                            content.style.display = "none";
                        }} else {{
                            content.style.display = "block";
                        }}
                    }}
                </script>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>SQL Injection Security Report</h1>
                        <p>Generated on {current_datetime}</p>
                    </div>
                    
                    <div class="summary">
                        <h2>Executive Summary</h2>
                        <p>This report presents the findings of a SQL injection vulnerability assessment conducted on the target application. The assessment was performed using automated testing techniques to identify potential security weaknesses.</p>
                        <p><strong>Risk Level:</strong> <span class="risk-badge">{risk_level}</span></p>
                        <p><strong>Target URL:</strong> {target_url}</p>
                        <p><strong>Tested Parameter:</strong> {parameter}</p>
                    </div>
                    
                    <div class="stats">
                        <div class="stat-box">
                            <h3>Vulnerabilities Found</h3>
                            <p>{vulnerabilities_found}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Total Tests</h3>
                            <p>{total_payloads}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Vulnerability Rate</h3>
                            <p>{vulnerability_percentage:.1f}%</p>
                            <div class="progress">
                                <div class="progress-bar" style="width: {vulnerability_percentage}%">{vulnerability_percentage:.1f}%</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2>Vulnerability Assessment</h2>
            """
            
            # Add vulnerability assessment based on results
            if vulnerabilities_found > 0:
                html_content += f"""
                        <p>The target application appears to be <strong>vulnerable to SQL injection attacks</strong>. Out of {total_payloads} test payloads, {vulnerabilities_found} ({vulnerability_percentage:.1f}%) triggered responses indicating potential SQL injection vulnerabilities.</p>
                        <p>SQL injection vulnerabilities can allow attackers to:</p>
                        <ul>
                            <li>Access sensitive data from the database</li>
                            <li>Bypass authentication mechanisms</li>
                            <li>Execute administrative operations on the database</li>
                            <li>In some cases, execute commands on the database server</li>
                        </ul>
                """
            else:
                html_content += f"""
                        <p>The target application does not appear to be vulnerable to SQL injection attacks based on our testing. None of the {total_payloads} test payloads triggered responses indicating SQL injection vulnerabilities.</p>
                        <p>However, this does not guarantee that the application is completely secure. We recommend implementing the security recommendations below as best practices.</p>
                """
            
            # Add recommendations section
            html_content += """
                    </div>
                    
                    <div class="recommendations">
                        <h2>Security Recommendations</h2>
                        <ul>
                            <li><strong>Use Parameterized Queries:</strong> Always use prepared statements or parameterized queries to separate SQL code from user input.</li>
                            <li><strong>Input Validation:</strong> Implement strict input validation for all user-supplied data.</li>
                            <li><strong>Least Privilege:</strong> Ensure database accounts used by applications have the minimum necessary privileges.</li>
                            <li><strong>Error Handling:</strong> Implement custom error handling to prevent detailed database errors from being displayed to users.</li>
                            <li><strong>WAF Implementation:</strong> Consider implementing a Web Application Firewall to provide an additional layer of protection.</li>
                            <li><strong>Regular Security Testing:</strong> Conduct regular security assessments and penetration testing.</li>
                        </ul>
                    </div>
            """
            
            # Add detailed results section
            html_content += """
                    <div class="section">
                        <h2>Detailed Test Results</h2>
                        <p class="details-toggle" onclick="toggleDetails('detailed-results')">Click to show/hide detailed results</p>
                        <div id="detailed-results" class="details-content">
                            <table>
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>Payload</th>
                                        <th>Status</th>
                                        <th>Response Length</th>
                                        <th>Response Time</th>
                                        <th>Result</th>
                                    </tr>
                                </thead>
                                <tbody>
            """
            
            # Add table rows for each test result
            for i, result in enumerate(results[:100], 1):  # Limit to first 100 results to avoid huge reports
                payload = result.get('payload', '')
                status_code = result.get('status_code', 0)
                response_length = result.get('response_length', 0)
                response_time = result.get('response_time', 0)
                vulnerability_detected = result.get('vulnerability_detected', False)
                detection_reason = result.get('detection_reason', '')
                
                result_class = 'vulnerable' if vulnerability_detected else 'safe'
                result_text = 'Vulnerable' if vulnerability_detected else 'Safe'
                
                html_content += f"""
                                    <tr>
                                        <td>{i}</td>
                                        <td><span class="code">{payload}</span></td>
                                        <td>{status_code}</td>
                                        <td>{response_length}</td>
                                        <td>{response_time} ms</td>
                                        <td class="{result_class}">{result_text}</td>
                                    </tr>
                """
            
            # Add note if results were limited
            if len(results) > 100:
                html_content += f"""
                                    <tr>
                                        <td colspan="6" style="text-align: center;">Showing 100 of {len(results)} results</td>
                                    </tr>
                """
            
            # Close table and add footer
            html_content += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>This report was generated by SQL Injection Testing Tool. The information provided is for security assessment purposes only.</p>
                        <p>© SQL Injection Testing Tool</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error Generating Report</title>
            </head>
            <body>
                <h1>Error Generating Report</h1>
                <p>{str(e)}</p>
            </body>
            </html>
            """
    
    def _generate_pdf_report(self, html_content, html_path):
        """
        Generate PDF report from HTML content.
        
        Args:
            html_content: HTML report content
            html_path: Path to saved HTML report
            
        Returns:
            tuple: (PDF content as bytes, PDF file path)
        """
        try:
            # Try to import pdfkit
            import pdfkit
            
            # Generate PDF filename from HTML filename
            pdf_path = html_path.replace('.html', '.pdf')
            
            # Generate PDF from HTML
            pdf_options = {
                'page-size': 'A4',
                'margin-top': '20mm',
                'margin-right': '20mm',
                'margin-bottom': '20mm',
                'margin-left': '20mm',
                'encoding': 'UTF-8',
                'no-outline': None,
                'enable-local-file-access': None
            }
            
            # Try to generate PDF
            pdfkit.from_string(html_content, pdf_path, options=pdf_options)
            
            # Read PDF content
            with open(pdf_path, 'rb') as f:
                pdf_content = f.read()
            
            return pdf_content, pdf_path
            
        except ImportError:
            logger.error("pdfkit not installed, cannot generate PDF report")
            raise ImportError("pdfkit not installed. Install with 'pip install pdfkit' and ensure wkhtmltopdf is installed.")
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise
