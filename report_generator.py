"""
AI-powered report generation for SQL injection test results.
Uses OpenAI to generate comprehensive security reports.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
import openai
from jinja2 import Template
import pdfkit
import base64

logger = logging.getLogger(__name__)

class SQLIReportGenerator:
    """
    Generates comprehensive SQL injection testing reports using OpenAI.
    """
    
    def __init__(self, openai_api_key=None):
        self.openai_api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        if self.openai_api_key:
            openai.api_key = self.openai_api_key
        else:
            logger.warning("OpenAI API key not provided. AI-powered features will be disabled.")
    
    def generate_ai_analysis(self, test_results: Dict) -> Dict:
        """
        Generate AI-powered analysis of SQL injection test results.
        
        Args:
            test_results: Dictionary containing test results
            
        Returns:
            Dictionary with AI analysis
        """
        if not self.openai_api_key:
            return self._generate_fallback_analysis(test_results)
        
        try:
            # Prepare data for AI analysis
            vulnerabilities = [r for r in test_results.get('results', []) if r.get('vulnerability_detected')]
            
            prompt = self._create_analysis_prompt(test_results, vulnerabilities)
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in SQL injection vulnerabilities. Provide detailed, professional analysis of security test results."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3
            )
            
            ai_analysis = response.choices[0].message.content
            
            return {
                'ai_powered': True,
                'executive_summary': self._extract_executive_summary(ai_analysis),
                'technical_analysis': self._extract_technical_analysis(ai_analysis),
                'risk_assessment': self._extract_risk_assessment(ai_analysis),
                'recommendations': self._extract_recommendations(ai_analysis),
                'full_analysis': ai_analysis
            }
            
        except Exception as e:
            logger.error(f"Error generating AI analysis: {e}")
            return self._generate_fallback_analysis(test_results)
    
    def _create_analysis_prompt(self, test_results: Dict, vulnerabilities: List) -> str:
        """Create prompt for AI analysis."""
        prompt = f"""
        Analyze the following SQL injection security test results:

        Target: {test_results.get('target_url', 'Unknown')}
        Parameter: {test_results.get('parameter', 'Unknown')}
        Total Payloads Tested: {test_results.get('total_payloads', 0)}
        Vulnerabilities Found: {test_results.get('vulnerabilities_found', 0)}

        Vulnerability Details:
        """
        
        for i, vuln in enumerate(vulnerabilities[:10], 1):  # Limit to first 10 for prompt size
            prompt += f"""
        {i}. Payload: {vuln.get('payload', 'Unknown')}
           Detection Reason: {vuln.get('detection_reason', 'Unknown')}
           Status Code: {vuln.get('status_code', 'Unknown')}
           Response Time: {vuln.get('response_time', 'Unknown')}ms
        """
        
        prompt += """
        
        Please provide a comprehensive security analysis including:
        1. Executive Summary (2-3 sentences)
        2. Technical Analysis (detailed technical findings)
        3. Risk Assessment (severity level and business impact)
        4. Recommendations (specific remediation steps)
        
        Format your response clearly with these sections.
        """
        
        return prompt
    
    def _extract_executive_summary(self, analysis: str) -> str:
        """Extract executive summary from AI analysis."""
        lines = analysis.split('\n')
        summary_lines = []
        in_summary = False
        
        for line in lines:
            if 'executive summary' in line.lower():
                in_summary = True
                continue
            elif in_summary and any(keyword in line.lower() for keyword in ['technical', 'risk', 'recommendation']):
                break
            elif in_summary and line.strip():
                summary_lines.append(line.strip())
        
        return '\n'.join(summary_lines) if summary_lines else "Security assessment completed with detailed findings."
    
    def _extract_technical_analysis(self, analysis: str) -> str:
        """Extract technical analysis from AI analysis."""
        lines = analysis.split('\n')
        tech_lines = []
        in_tech = False
        
        for line in lines:
            if 'technical analysis' in line.lower():
                in_tech = True
                continue
            elif in_tech and any(keyword in line.lower() for keyword in ['risk', 'recommendation']):
                break
            elif in_tech and line.strip():
                tech_lines.append(line.strip())
        
        return '\n'.join(tech_lines) if tech_lines else "Technical analysis of SQL injection vulnerabilities performed."
    
    def _extract_risk_assessment(self, analysis: str) -> str:
        """Extract risk assessment from AI analysis."""
        lines = analysis.split('\n')
        risk_lines = []
        in_risk = False
        
        for line in lines:
            if 'risk assessment' in line.lower():
                in_risk = True
                continue
            elif in_risk and 'recommendation' in line.lower():
                break
            elif in_risk and line.strip():
                risk_lines.append(line.strip())
        
        return '\n'.join(risk_lines) if risk_lines else "Risk assessment indicates potential security vulnerabilities."
    
    def _extract_recommendations(self, analysis: str) -> str:
        """Extract recommendations from AI analysis."""
        lines = analysis.split('\n')
        rec_lines = []
        in_rec = False
        
        for line in lines:
            if 'recommendation' in line.lower():
                in_rec = True
                continue
            elif in_rec and line.strip():
                rec_lines.append(line.strip())
        
        return '\n'.join(rec_lines) if rec_lines else "Implement proper input validation and parameterized queries."
    
    def _generate_fallback_analysis(self, test_results: Dict) -> Dict:
        """Generate fallback analysis when AI is not available."""
        vulnerabilities_found = test_results.get('vulnerabilities_found', 0)
        total_payloads = test_results.get('total_payloads', 0)
        
        if vulnerabilities_found == 0:
            risk_level = "LOW"
            summary = "No SQL injection vulnerabilities detected during testing."
        elif vulnerabilities_found < total_payloads * 0.1:
            risk_level = "MEDIUM"
            summary = f"Limited SQL injection vulnerabilities detected ({vulnerabilities_found} out of {total_payloads} payloads)."
        else:
            risk_level = "HIGH"
            summary = f"Multiple SQL injection vulnerabilities detected ({vulnerabilities_found} out of {total_payloads} payloads)."
        
        return {
            'ai_powered': False,
            'executive_summary': summary,
            'technical_analysis': f"Automated testing identified {vulnerabilities_found} potential SQL injection points in the target application.",
            'risk_assessment': f"Risk Level: {risk_level}. Immediate attention required for remediation.",
            'recommendations': "1. Implement parameterized queries\n2. Use input validation\n3. Apply principle of least privilege\n4. Regular security testing",
            'full_analysis': f"Standard security analysis completed. {summary}"
        }
    
    def generate_html_report(self, test_results: Dict, ai_analysis: Dict, user_info: Dict = None) -> str:
        """
        Generate HTML report from test results.
        
        Args:
            test_results: Test results dictionary
            ai_analysis: AI analysis dictionary
            user_info: User information dictionary
            
        Returns:
            HTML report string
        """
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .meta-card {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .meta-card h3 {
            margin: 0 0 10px 0;
            color: #2c3e50;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .vulnerability-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .summary-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            color: white;
        }
        .summary-card.total {
            background: #3498db;
        }
        .summary-card.vulnerable {
            background: #e74c3c;
        }
        .summary-card.safe {
            background: #27ae60;
        }
        .summary-card h3 {
            margin: 0;
            font-size: 2em;
        }
        .summary-card p {
            margin: 5px 0 0 0;
        }
        .vulnerability-list {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
        }
        .vulnerability-item {
            background: white;
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #e74c3c;
        }
        .vulnerability-item:last-child {
            margin-bottom: 0;
        }
        .payload {
            font-family: 'Courier New', monospace;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            word-break: break-all;
        }
        .risk-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .risk-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .risk-low {
            color: #27ae60;
            font-weight: bold;
        }
        .ai-badge {
            background: linear-gradient(45deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            display: inline-block;
            margin-left: 10px;
        }
        .recommendations {
            background: #e8f5e8;
            border: 1px solid #27ae60;
            border-radius: 8px;
            padding: 20px;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #bdc3c7;
            color: #7f8c8d;
        }
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
                padding: 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SQL Injection Security Assessment</h1>
            <div class="subtitle">Comprehensive Vulnerability Analysis Report</div>
            {% if ai_analysis.ai_powered %}
            <span class="ai-badge">🤖 AI-Powered Analysis</span>
            {% endif %}
        </div>

        <div class="meta-info">
            <div class="meta-card">
                <h3>📅 Report Date</h3>
                <p>{{ report_date }}</p>
            </div>
            <div class="meta-card">
                <h3>🎯 Target URL</h3>
                <p>{{ test_results.target_url }}</p>
            </div>
            <div class="meta-card">
                <h3>🏷️ Parameter</h3>
                <p>{{ test_results.parameter }}</p>
            </div>
            <div class="meta-card">
                <h3>🔧 Method</h3>
                <p>{{ test_results.method or 'GET' }}</p>
            </div>
            {% if user_info %}
            <div class="meta-card">
                <h3>👤 Tested By</h3>
                <p>{{ user_info.username }}</p>
            </div>
            {% endif %}
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p>{{ ai_analysis.executive_summary }}</p>
        </div>

        <div class="section">
            <h2>📈 Test Results Overview</h2>
            <div class="vulnerability-summary">
                <div class="summary-card total">
                    <h3>{{ test_results.total_payloads }}</h3>
                    <p>Total Payloads Tested</p>
                </div>
                <div class="summary-card vulnerable">
                    <h3>{{ test_results.vulnerabilities_found }}</h3>
                    <p>Vulnerabilities Found</p>
                </div>
                <div class="summary-card safe">
                    <h3>{{ test_results.total_payloads - test_results.vulnerabilities_found }}</h3>
                    <p>Safe Responses</p>
                </div>
            </div>
        </div>

        {% if test_results.vulnerabilities_found > 0 %}
        <div class="section">
            <h2>🚨 Vulnerability Details</h2>
            <div class="vulnerability-list">
                {% for vuln in vulnerabilities[:10] %}
                <div class="vulnerability-item">
                    <h4>Vulnerability #{{ loop.index }}</h4>
                    <p><strong>Detection Reason:</strong> {{ vuln.detection_reason }}</p>
                    <p><strong>Status Code:</strong> {{ vuln.status_code }} | <strong>Response Time:</strong> {{ vuln.response_time }}ms</p>
                    <div class="payload">{{ vuln.payload }}</div>
                </div>
                {% endfor %}
                {% if vulnerabilities|length > 10 %}
                <p><em>... and {{ vulnerabilities|length - 10 }} more vulnerabilities found.</em></p>
                {% endif %}
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2>🔍 Technical Analysis</h2>
            <p>{{ ai_analysis.technical_analysis }}</p>
        </div>

        <div class="section">
            <h2>⚠️ Risk Assessment</h2>
            <p>{{ ai_analysis.risk_assessment }}</p>
        </div>

        <div class="section">
            <h2>💡 Recommendations</h2>
            <div class="recommendations">
                <pre>{{ ai_analysis.recommendations }}</pre>
            </div>
        </div>

        <div class="footer">
            <p>Report generated by SQL Injector v2.0 | {{ report_date }}</p>
            <p>⚖️ This report is for authorized security testing only</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        
        # Prepare vulnerabilities list
        vulnerabilities = [r for r in test_results.get('results', []) if r.get('vulnerability_detected')]
        
        return template.render(
            test_results=test_results,
            ai_analysis=ai_analysis,
            user_info=user_info,
            vulnerabilities=vulnerabilities,
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    def generate_pdf_report(self, html_content: str) -> bytes:
        """
        Generate PDF report from HTML content.
        
        Args:
            html_content: HTML content string
            
        Returns:
            PDF content as bytes
        """
        try:
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None
            }
            
            pdf_content = pdfkit.from_string(html_content, False, options=options)
            return pdf_content
            
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            raise
    
    def generate_complete_report(self, test_results: Dict, user_info: Dict = None, format_type: str = 'html') -> Dict:
        """
        Generate complete report with AI analysis.
        
        Args:
            test_results: Test results dictionary
            user_info: User information dictionary
            format_type: 'html' or 'pdf'
            
        Returns:
            Dictionary with report data
        """
        try:
            # Generate AI analysis
            ai_analysis = self.generate_ai_analysis(test_results)
            
            # Generate HTML report
            html_content = self.generate_html_report(test_results, ai_analysis, user_info)
            
            report_data = {
                'ai_analysis': ai_analysis,
                'html_content': html_content,
                'format': format_type,
                'generated_at': datetime.now().isoformat()
            }
            
            # Generate PDF if requested
            if format_type == 'pdf':
                try:
                    pdf_content = self.generate_pdf_report(html_content)
                    report_data['pdf_content'] = base64.b64encode(pdf_content).decode('utf-8')
                except Exception as e:
                    logger.error(f"PDF generation failed: {e}")
                    report_data['pdf_error'] = str(e)
            
            return report_data
            
        except Exception as e:
            logger.error(f"Error generating complete report: {e}")
            raise

# Example usage
if __name__ == "__main__":
    # Example test results
    test_results = {
        'target_url': 'https://example.com/page.php?id=1',
        'parameter': 'id',
        'method': 'GET',
        'total_payloads': 100,
        'vulnerabilities_found': 5,
        'results': [
            {
                'payload': "' OR 1=1--",
                'vulnerability_detected': True,
                'detection_reason': 'SQL error pattern detected',
                'status_code': 500,
                'response_time': 1200
            }
        ]
    }
    
    # Generate report
    generator = SQLIReportGenerator()
    report = generator.generate_complete_report(test_results)
    print("Report generated successfully!")
