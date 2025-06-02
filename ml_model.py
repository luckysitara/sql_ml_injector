"""
Machine Learning model for SQL injection detection using Random Forest.
This version loads pre-trained Random Forest model from disk.
"""

import os
import numpy as np
import pickle
import logging
import json
import re
import time

# Setup logging
logger = logging.getLogger(__name__)

class SQLInjectionMLModel:
    """
    Machine Learning model for SQL injection detection using pre-trained Random Forest model.
    """
    
    def __init__(self, model_dir='models'):
        """
        Initialize the ML model by loading pre-trained Random Forest model from disk.
        
        Args:
            model_dir: Directory containing the pre-trained models
        """
        self.model_dir = model_dir
        self.rf_model = None
        self.vectorizer = None
        
        # Create models directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Load models if available
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained Random Forest model and vectorizer from disk."""
        try:
            # Try to load Random Forest model
            rf_path = os.path.join(self.model_dir, 'rf_model.pkl')
            if os.path.exists(rf_path):
                try:
                    import joblib
                    self.rf_model = joblib.load(rf_path)
                    logger.info(f"Random Forest model loaded from {rf_path}")
                except Exception as e:
                    logger.error(f"Error loading Random Forest model: {e}")
            else:
                logger.warning(f"Random Forest model not found at {rf_path}")
            
            # Try to load vectorizer
            vectorizer_path = os.path.join(self.model_dir, 'vectorizer.pkl')
            if os.path.exists(vectorizer_path):
                try:
                    import joblib
                    self.vectorizer = joblib.load(vectorizer_path)
                    logger.info(f"Vectorizer loaded from {vectorizer_path}")
                except Exception as e:
                    logger.error(f"Error loading vectorizer: {e}")
            else:
                logger.warning(f"Vectorizer not found at {vectorizer_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False
    
    def get_model_info(self):
        """
        Get information about the loaded models.
        
        Returns:
            dict: Information about the loaded models
        """
        return {
            'rf_loaded': self.rf_model is not None,
            'vectorizer_loaded': self.vectorizer is not None,
            'models_directory': self.model_dir,
            'model_type': 'Random Forest',
            'models_available': {
                'rf': os.path.exists(os.path.join(self.model_dir, 'rf_model.pkl')),
                'vectorizer': os.path.exists(os.path.join(self.model_dir, 'vectorizer.pkl'))
            }
        }
    
    def predict_vulnerability(self, query):
        """
        Predict if a query is vulnerable to SQL injection using Random Forest.
        
        Args:
            query: SQL query to analyze
            
        Returns:
            dict: Prediction results with confidence score and risk level
        """
        # Default response if models aren't loaded
        default_response = {
            'is_vulnerable': False,
            'confidence': 0.0,
            'risk_level': 'MINIMAL',
            'model_used': 'none',
            'error': 'Models not loaded'
        }
        
        try:
            # Check if models are loaded
            if self.rf_model is None or self.vectorizer is None:
                logger.warning("Random Forest model or vectorizer not loaded")
                return default_response
            
            # Preprocess the query
            if not isinstance(query, str):
                query = str(query)
            
            # Vectorize the query using TF-IDF
            try:
                vectorized = self.vectorizer.transform([query]).toarray()
            except Exception as e:
                logger.error(f"Error vectorizing query: {e}")
                return default_response
            
            # Get prediction probability
            try:
                rf_proba = self.rf_model.predict_proba(vectorized)[0]
                rf_score = float(rf_proba[1])  # Probability of being malicious
                rf_pred = self.rf_model.predict(vectorized)[0]
            except Exception as e:
                logger.error(f"Error in Random Forest prediction: {e}")
                return default_response
            
            # Determine vulnerability and risk level
            is_vulnerable = rf_pred == 1 or rf_score > 0.5
            
            # Calculate risk level based on confidence score
            if rf_score >= 0.9:
                risk_level = 'HIGH'
            elif rf_score >= 0.7:
                risk_level = 'MEDIUM'
            elif rf_score >= 0.5:
                risk_level = 'LOW'
            else:
                risk_level = 'MINIMAL'
            
            return {
                'is_vulnerable': is_vulnerable,
                'confidence': rf_score,
                'risk_level': risk_level,
                'model_used': 'random_forest',
                'prediction_details': {
                    'benign_probability': float(rf_proba[0]),
                    'malicious_probability': float(rf_proba[1]),
                    'binary_prediction': int(rf_pred)
                }
            }
            
        except Exception as e:
            logger.error(f"Error predicting vulnerability: {e}")
            return {
                'is_vulnerable': False,
                'confidence': 0.0,
                'risk_level': 'MINIMAL',
                'model_used': 'none',
                'error': str(e)
            }
    
    def analyze_response_patterns(self, response_text, status_code, response_time):
        """
        Analyze response patterns for signs of SQL injection vulnerability.
        
        Args:
            response_text: HTTP response text
            status_code: HTTP status code
            response_time: Response time in milliseconds
            
        Returns:
            dict: Analysis results
        """
        try:
            # Initialize scores
            error_score = 0.0
            time_score = 0.0
            content_score = 0.0
            status_score = 0.0
            
            # Check for common SQL error patterns
            sql_error_patterns = [
                r'sql syntax',
                r'syntax error',
                r'mysql error',
                r'oracle error',
                r'sql server error',
                r'postgresql error',
                r'sqlite error',
                r'database error',
                r'odbc error',
                r'jdbc error',
                r'ora-\d+',
                r'pg_query',
                r'quoted string not properly terminated',
                r'unclosed quotation mark',
                r'unterminated string',
                r'division by zero',
                r'supplied argument is not a valid mysql',
                r'warning: mysql_',
                r'function\.mysql',
                r'mysql_fetch_array',
                r'on line \d+ of',
                r'you have an error in your sql syntax',
                r'call to a member function',
                r'invalid query',
                r'sql command not properly ended',
                r'error in your sql syntax',
                r'warning: pg_',
                r'warning: mysql',
                r'function\.pg',
                r'postgres_',
                r'driver.*sql[-_ ]*server',
                r'ole db.*sql server',
                r'microsoft odbc',
                r'microsoft sql',
                r'sql server.*driver',
                r'sql server.*\[',
                r'unclosed quotation mark after the character string',
                r'incorrect syntax near',
                r'unexpected end of command',
                r'unexpected token',
                r'sql state'
            ]
            
            # Check for error patterns in response
            for pattern in sql_error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    error_score += 0.3
                    break
            
            # Check for suspicious status codes
            if status_code == 500:
                status_score = 0.7
            elif status_code in [400, 403, 503]:
                status_score = 0.3
            
            # Check for time-based indicators
            if response_time > 5000:  # More than 5 seconds
                time_score = 0.8
            elif response_time > 2000:  # More than 2 seconds
                time_score = 0.4
            
            # Check for content-based indicators
            if len(response_text) == 0:
                content_score = 0.5
            elif 'admin' in response_text.lower() and ('id' in response_text.lower() or 'user' in response_text.lower()):
                content_score = 0.6
            elif 'root' in response_text.lower() and ('system' in response_text.lower() or 'mysql' in response_text.lower()):
                content_score = 0.7
            
            # Calculate overall confidence score
            confidence_score = max(
                error_score,
                time_score,
                content_score,
                status_score
            )
            
            # Determine risk level based on confidence
            if confidence_score >= 0.7:
                risk_level = 'HIGH'
            elif confidence_score >= 0.5:
                risk_level = 'MEDIUM'
            elif confidence_score >= 0.3:
                risk_level = 'LOW'
            else:
                risk_level = 'MINIMAL'
            
            return {
                'confidence_score': confidence_score,
                'risk_level': risk_level,
                'error_score': error_score,
                'time_score': time_score,
                'content_score': content_score,
                'status_score': status_score,
                'response_analysis': {
                    'status_code': status_code,
                    'response_time': response_time,
                    'response_length': len(response_text),
                    'contains_error_pattern': error_score > 0
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing response patterns: {e}")
            return {
                'confidence_score': 0.0,
                'risk_level': 'MINIMAL',
                'error_score': 0.0,
                'time_score': 0.0,
                'content_score': 0.0,
                'status_score': 0.0,
                'response_analysis': {
                    'status_code': status_code,
                    'response_time': response_time,
                    'response_length': len(response_text) if response_text else 0,
                    'contains_error_pattern': False
                }
            }
    
    def batch_predict(self, queries):
        """
        Predict vulnerabilities for multiple queries at once.
        
        Args:
            queries: List of SQL queries to analyze
            
        Returns:
            list: List of prediction results
        """
        results = []
        for query in queries:
            result = self.predict_vulnerability(query)
            results.append(result)
        return results
    
    def get_feature_importance(self, top_n=20):
        """
        Get feature importance from the Random Forest model.
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            dict: Feature importance information
        """
        try:
            if self.rf_model is None or self.vectorizer is None:
                return {'error': 'Models not loaded'}
            
            # Get feature names from vectorizer
            feature_names = self.vectorizer.get_feature_names_out()
            
            # Get feature importance from Random Forest
            importance_scores = self.rf_model.feature_importances_
            
            # Create feature importance pairs
            feature_importance = list(zip(feature_names, importance_scores))
            
            # Sort by importance (descending)
            feature_importance.sort(key=lambda x: x[1], reverse=True)
            
            # Get top N features
            top_features = feature_importance[:top_n]
            
            return {
                'top_features': [{'feature': feat, 'importance': float(imp)} for feat, imp in top_features],
                'total_features': len(feature_names),
                'model_type': 'Random Forest'
            }
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
            return {'error': str(e)}
