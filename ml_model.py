"""
Machine Learning model for SQL injection vulnerability detection.
Trains and uses LSTM model to analyze SQL injection responses.
"""

import numpy as np
import pandas as pd
import pickle
import os
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import (
    Embedding, LSTM, Dense, Dropout, Input, 
    BatchNormalization, Bidirectional, SpatialDropout1D
)
from tensorflow.keras.callbacks import EarlyStopping
import joblib

logger = logging.getLogger(__name__)

class SQLInjectionMLModel:
    """
    Machine Learning model for SQL injection detection using LSTM and traditional ML approaches.
    """
    
    def __init__(self, model_dir='models'):
        self.model_dir = model_dir
        self.lstm_model = None
        self.rf_model = None
        self.tokenizer = None
        self.vectorizer = None
        self.max_len = 100
        self.max_words = 20000
        self.embedding_dim = 100
        
        # Create models directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Try to load existing models
        self.load_models()
    
    def prepare_data(self, csv_path):
        """
        Prepare data from CSV file for training.
        
        Args:
            csv_path: Path to the CSV file with Query and Label columns
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test, sequences_train, sequences_test)
        """
        try:
            # Load dataset
            logger.info(f"Loading dataset from {csv_path}")
            data = pd.read_csv(csv_path)
            
            # Check if required columns exist
            if 'Query' not in data.columns or 'Label' not in data.columns:
                raise ValueError("CSV must contain 'Query' and 'Label' columns")
            
            # Clean data
            data = data.dropna()
            data['Query'] = data['Query'].astype(str)
            data['Label'] = data['Label'].astype(int)
            
            logger.info(f"Dataset loaded: {len(data)} samples")
            logger.info(f"Malicious samples: {sum(data['Label'])}")
            logger.info(f"Benign samples: {len(data) - sum(data['Label'])}")
            
            # Split data
            train_data, test_data = train_test_split(data, test_size=0.2, random_state=42, stratify=data['Label'])
            
            # Prepare traditional ML features (TF-IDF)
            self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
            X_train = self.vectorizer.fit_transform(train_data['Query']).toarray()
            X_test = self.vectorizer.transform(test_data['Query']).toarray()
            
            # Prepare LSTM features (tokenized sequences)
            self.tokenizer = Tokenizer(num_words=self.max_words, oov_token='<OOV>')
            self.tokenizer.fit_on_texts(train_data['Query'])
            
            sequences_train = self.tokenizer.texts_to_sequences(train_data['Query'])
            sequences_test = self.tokenizer.texts_to_sequences(test_data['Query'])
            
            sequences_train = pad_sequences(sequences_train, maxlen=self.max_len)
            sequences_test = pad_sequences(sequences_test, maxlen=self.max_len)
            
            y_train = train_data['Label'].values
            y_test = test_data['Label'].values
            
            return X_train, X_test, y_train, y_test, sequences_train, sequences_test
            
        except Exception as e:
            logger.error(f"Error preparing data: {e}")
            raise
    
    def create_lstm_model(self):
        """
        Create LSTM model architecture.
        
        Returns:
            Compiled Keras model
        """
        # Input layer
        input_text = Input(shape=(self.max_len,), dtype='int32')
        
        # Embedding layer
        embedding_layer = Embedding(
            self.max_words,
            self.embedding_dim,
            input_length=self.max_len
        )(input_text)
        
        # LSTM layers with regularization
        x = SpatialDropout1D(0.3)(embedding_layer)
        x = Bidirectional(LSTM(128, return_sequences=True))(x)
        x = BatchNormalization()(x)
        x = Dropout(0.5)(x)
        
        x = Bidirectional(LSTM(64, return_sequences=True))(x)
        x = BatchNormalization()(x)
        x = Dropout(0.5)(x)
        
        x = Bidirectional(LSTM(32))(x)
        x = BatchNormalization()(x)
        x = Dropout(0.5)(x)
        
        # Dense layers
        x = Dense(64, activation='relu')(x)
        x = Dropout(0.5)(x)
        
        # Output layer
        predictions = Dense(1, activation='sigmoid')(x)
        
        # Create and compile model
        model = Model(inputs=input_text, outputs=predictions)
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train_models(self, csv_path, epochs=25):
        """
        Train both LSTM and Random Forest models.
        
        Args:
            csv_path: Path to training data CSV
            epochs: Number of epochs for LSTM training
            
        Returns:
            Dictionary with training results
        """
        try:
            logger.info("Starting model training...")
            
            # Prepare data
            X_train, X_test, y_train, y_test, sequences_train, sequences_test = self.prepare_data(csv_path)
            
            # Train Random Forest model
            logger.info("Training Random Forest model...")
            self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
            self.rf_model.fit(X_train, y_train)
            
            # Evaluate Random Forest
            rf_pred = self.rf_model.predict(X_test)
            rf_proba = self.rf_model.predict_proba(X_test)[:, 1]
            
            rf_metrics = {
                'accuracy': accuracy_score(y_test, rf_pred),
                'precision': precision_score(y_test, rf_pred),
                'recall': recall_score(y_test, rf_pred),
                'f1': f1_score(y_test, rf_pred),
                'roc_auc': roc_auc_score(y_test, rf_proba)
            }
            
            logger.info(f"Random Forest metrics: {rf_metrics}")
            
            # Train LSTM model
            logger.info("Training LSTM model...")
            self.lstm_model = self.create_lstm_model()
            
            # Early stopping callback
            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True
            )
            
            # Train LSTM
            history = self.lstm_model.fit(
                sequences_train, y_train,
                epochs=epochs,
                batch_size=32,
                validation_split=0.2,
                callbacks=[early_stopping],
                verbose=1
            )
            
            # Evaluate LSTM
            lstm_pred_proba = self.lstm_model.predict(sequences_test)
            lstm_pred = (lstm_pred_proba > 0.5).astype(int).flatten()
            
            lstm_metrics = {
                'accuracy': accuracy_score(y_test, lstm_pred),
                'precision': precision_score(y_test, lstm_pred),
                'recall': recall_score(y_test, lstm_pred),
                'f1': f1_score(y_test, lstm_pred),
                'roc_auc': roc_auc_score(y_test, lstm_pred_proba)
            }
            
            logger.info(f"LSTM metrics: {lstm_metrics}")
            
            # Save models
            self.save_models()
            
            return {
                'rf_metrics': rf_metrics,
                'lstm_metrics': lstm_metrics,
                'training_history': history.history
            }
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            raise
    
    def predict_vulnerability(self, query_text, method='ensemble'):
        """
        Predict if a query is a SQL injection attempt.
        
        Args:
            query_text: SQL query text to analyze
            method: 'lstm', 'rf', or 'ensemble'
            
        Returns:
            Dictionary with prediction results
        """
        try:
            if not isinstance(query_text, str):
                query_text = str(query_text)
            
            results = {
                'query': query_text,
                'is_vulnerable': False,
                'confidence': 0.0,
                'method': method,
                'predictions': {}
            }
            
            # LSTM prediction
            if self.lstm_model and self.tokenizer and method in ['lstm', 'ensemble']:
                sequence = self.tokenizer.texts_to_sequences([query_text])
                padded_sequence = pad_sequences(sequence, maxlen=self.max_len)
                lstm_prob = float(self.lstm_model.predict(padded_sequence, verbose=0)[0][0])
                results['predictions']['lstm'] = {
                    'probability': lstm_prob,
                    'is_vulnerable': lstm_prob > 0.5
                }
            
            # Random Forest prediction
            if self.rf_model and self.vectorizer and method in ['rf', 'ensemble']:
                vectorized = self.vectorizer.transform([query_text]).toarray()
                rf_prob = float(self.rf_model.predict_proba(vectorized)[0][1])
                results['predictions']['rf'] = {
                    'probability': rf_prob,
                    'is_vulnerable': rf_prob > 0.5
                }
            
            # Ensemble prediction (weighted average)
            if method == 'ensemble' and 'lstm' in results['predictions'] and 'rf' in results['predictions']:
                # Weight LSTM more heavily as it typically performs better
                ensemble_prob = (0.7 * results['predictions']['lstm']['probability'] + 
                               0.3 * results['predictions']['rf']['probability'])
                results['confidence'] = ensemble_prob
                results['is_vulnerable'] = ensemble_prob > 0.5
            elif method == 'lstm' and 'lstm' in results['predictions']:
                results['confidence'] = results['predictions']['lstm']['probability']
                results['is_vulnerable'] = results['predictions']['lstm']['is_vulnerable']
            elif method == 'rf' and 'rf' in results['predictions']:
                results['confidence'] = results['predictions']['rf']['probability']
                results['is_vulnerable'] = results['predictions']['rf']['is_vulnerable']
            
            return results
            
        except Exception as e:
            logger.error(f"Error predicting vulnerability: {e}")
            return {
                'query': query_text,
                'is_vulnerable': False,
                'confidence': 0.0,
                'method': method,
                'error': str(e)
            }
    
    def analyze_response_patterns(self, response_text, status_code, response_time):
        """
        Analyze HTTP response patterns for SQL injection indicators.
        
        Args:
            response_text: HTTP response body
            status_code: HTTP status code
            response_time: Response time in milliseconds
            
        Returns:
            Dictionary with analysis results
        """
        indicators = {
            'error_patterns': [],
            'suspicious_patterns': [],
            'timing_anomaly': False,
            'status_anomaly': False,
            'confidence_score': 0.0
        }
        
        # SQL error patterns
        error_patterns = [
            r'mysql_fetch_array',
            r'ORA-\d+',
            r'Microsoft.*ODBC.*SQL Server',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql_',
            r'SQL syntax.*MySQL',
            r'sqlite3.*OperationalError',
            r'SQLSTATE',
            r'syntax error',
            r'unterminated quoted string'
        ]
        
        # Check for error patterns
        import re
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators['error_patterns'].append(pattern)
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'database.*error',
            r'sql.*error',
            r'invalid.*query',
            r'query.*failed',
            r'blocked',
            r'forbidden',
            r'access.*denied'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators['suspicious_patterns'].append(pattern)
        
        # Check timing anomaly (response time > 5 seconds)
        if response_time > 5000:
            indicators['timing_anomaly'] = True
        
        # Check status code anomaly
        if status_code in [500, 403, 406, 501, 999]:
            indicators['status_anomaly'] = True
        
        # Calculate confidence score
        score = 0.0
        if indicators['error_patterns']:
            score += 0.4
        if indicators['suspicious_patterns']:
            score += 0.2
        if indicators['timing_anomaly']:
            score += 0.2
        if indicators['status_anomaly']:
            score += 0.2
        
        indicators['confidence_score'] = min(score, 1.0)
        
        return indicators
    
    def save_models(self):
        """Save trained models to disk."""
        try:
            # Save LSTM model
            if self.lstm_model:
                lstm_path = os.path.join(self.model_dir, 'lstm_model.h5')
                self.lstm_model.save(lstm_path)
                logger.info(f"LSTM model saved to {lstm_path}")
            
            # Save Random Forest model
            if self.rf_model:
                rf_path = os.path.join(self.model_dir, 'rf_model.pkl')
                joblib.dump(self.rf_model, rf_path)
                logger.info(f"Random Forest model saved to {rf_path}")
            
            # Save tokenizer
            if self.tokenizer:
                tokenizer_path = os.path.join(self.model_dir, 'tokenizer.pkl')
                with open(tokenizer_path, 'wb') as f:
                    pickle.dump(self.tokenizer, f)
                logger.info(f"Tokenizer saved to {tokenizer_path}")
            
            # Save vectorizer
            if self.vectorizer:
                vectorizer_path = os.path.join(self.model_dir, 'vectorizer.pkl')
                joblib.dump(self.vectorizer, vectorizer_path)
                logger.info(f"Vectorizer saved to {vectorizer_path}")
                
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def load_models(self):
        """Load trained models from disk."""
        try:
            # Load LSTM model
            lstm_path = os.path.join(self.model_dir, 'lstm_model.h5')
            if os.path.exists(lstm_path):
                self.lstm_model = load_model(lstm_path)
                logger.info("LSTM model loaded successfully")
            
            # Load Random Forest model
            rf_path = os.path.join(self.model_dir, 'rf_model.pkl')
            if os.path.exists(rf_path):
                self.rf_model = joblib.load(rf_path)
                logger.info("Random Forest model loaded successfully")
            
            # Load tokenizer
            tokenizer_path = os.path.join(self.model_dir, 'tokenizer.pkl')
            if os.path.exists(tokenizer_path):
                with open(tokenizer_path, 'rb') as f:
                    self.tokenizer = pickle.load(f)
                logger.info("Tokenizer loaded successfully")
            
            # Load vectorizer
            vectorizer_path = os.path.join(self.model_dir, 'vectorizer.pkl')
            if os.path.exists(vectorizer_path):
                self.vectorizer = joblib.load(vectorizer_path)
                logger.info("Vectorizer loaded successfully")
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
    
    def get_model_info(self):
        """Get information about loaded models."""
        info = {
            'lstm_loaded': self.lstm_model is not None,
            'rf_loaded': self.rf_model is not None,
            'tokenizer_loaded': self.tokenizer is not None,
            'vectorizer_loaded': self.vectorizer is not None,
            'models_available': []
        }
        
        if self.lstm_model and self.tokenizer:
            info['models_available'].append('lstm')
        if self.rf_model and self.vectorizer:
            info['models_available'].append('rf')
        if len(info['models_available']) >= 2:
            info['models_available'].append('ensemble')
        
        return info

# Example usage and testing
if __name__ == "__main__":
    # Initialize model
    ml_model = SQLInjectionMLModel()
    
    # Example prediction
    test_queries = [
        "SELECT * FROM users WHERE id = 1",
        "' OR 1=1--",
        "admin' OR '1'='1",
        "SELECT * FROM products WHERE name = 'laptop'"
    ]
    
    for query in test_queries:
        result = ml_model.predict_vulnerability(query)
        print(f"Query: {query}")
        print(f"Vulnerable: {result['is_vulnerable']}")
        print(f"Confidence: {result['confidence']:.3f}")
        print("-" * 50)
