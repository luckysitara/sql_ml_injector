# SQL Injection ML Model Training in Google Colab
# ===============================================

import os
import numpy as np
import pandas as pd
import pickle
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import (
    Embedding, LSTM, Dense, Dropout, Input, 
    BatchNormalization, Bidirectional, SpatialDropout1D
)
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.utils import plot_model
import joblib
from google.colab import drive
import time

# Mount Google Drive
print("Mounting Google Drive...")
drive.mount('/content/drive')

# Create directories for saving models
MODELS_DIR = '/content/drive/MyDrive/sql_injection_models'
os.makedirs(MODELS_DIR, exist_ok=True)
print(f"Models will be saved to: {MODELS_DIR}")

# Configuration
MAX_LEN = 100
MAX_WORDS = 20000
EMBEDDING_DIM = 100
BATCH_SIZE = 64
EPOCHS = 25
VALIDATION_SPLIT = 0.2

class SQLInjectionMLModel:
    """
    Machine Learning model for SQL injection detection using LSTM and traditional ML approaches.
    """
    
    def __init__(self, model_dir=MODELS_DIR):
        self.model_dir = model_dir
        self.lstm_model = None
        self.rf_model = None
        self.tokenizer = None
        self.vectorizer = None
        self.max_len = MAX_LEN
        self.max_words = MAX_WORDS
        self.embedding_dim = EMBEDDING_DIM
        
        # Create models directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
    
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
            print(f"Loading dataset from {csv_path}")
            data = pd.read_csv(csv_path)
            
            # Check if required columns exist
            if 'Query' not in data.columns or 'Label' not in data.columns:
                raise ValueError("CSV must contain 'Query' and 'Label' columns")
            
            # Clean data
            data = data.dropna()
            data['Query'] = data['Query'].astype(str)
            data['Label'] = data['Label'].astype(int)
            
            print(f"Dataset loaded: {len(data)} samples")
            print(f"Malicious samples: {sum(data['Label'])}")
            print(f"Benign samples: {len(data) - sum(data['Label'])}")
            
            # Display sample data
            print("\nSample data:")
            print(data.head())
            
            # Class distribution
            print("\nClass distribution:")
            print(data['Label'].value_counts())
            
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
            
            # Print shapes for debugging
            print(f"\nTraining data shapes:")
            print(f"X_train (TF-IDF): {X_train.shape}")
            print(f"sequences_train (LSTM): {sequences_train.shape}")
            print(f"y_train: {y_train.shape}")
            
            print(f"\nTest data shapes:")
            print(f"X_test (TF-IDF): {X_test.shape}")
            print(f"sequences_test (LSTM): {sequences_test.shape}")
            print(f"y_test: {y_test.shape}")
            
            return X_train, X_test, y_train, y_test, sequences_train, sequences_test
            
        except Exception as e:
            print(f"Error preparing data: {e}")
            raise
    
    def create_lstm_model(self):
        """
        Create LSTM model architecture.
        
        Returns:
            Compiled Keras model
        """
        # Input layer
        input_text = Input(shape=(self.max_len,), dtype='int32', name='input_layer')
        
        # Embedding layer
        embedding_layer = Embedding(
            self.max_words,
            self.embedding_dim,
            input_length=self.max_len,
            name='embedding_layer'
        )(input_text)
        
        # LSTM layers with regularization
        x = SpatialDropout1D(0.3, name='spatial_dropout_1')(embedding_layer)
        x = Bidirectional(LSTM(128, return_sequences=True, name='lstm_1'))(x)
        x = BatchNormalization(name='batch_norm_1')(x)
        x = Dropout(0.5, name='dropout_1')(x)
        
        x = Bidirectional(LSTM(64, return_sequences=True, name='lstm_2'))(x)
        x = BatchNormalization(name='batch_norm_2')(x)
        x = Dropout(0.5, name='dropout_2')(x)
        
        x = Bidirectional(LSTM(32, name='lstm_3'))(x)
        x = BatchNormalization(name='batch_norm_3')(x)
        x = Dropout(0.5, name='dropout_3')(x)
        
        # Dense layers
        x = Dense(64, activation='relu', name='dense_1')(x)
        x = Dropout(0.5, name='dropout_4')(x)
        
        # Output layer
        predictions = Dense(1, activation='sigmoid', name='output_layer')(x)
        
        # Create and compile model
        model = Model(inputs=input_text, outputs=predictions)
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        # Print model summary
        model.summary()
        
        # Plot model architecture
        try:
            plot_model(model, to_file=os.path.join(self.model_dir, 'lstm_model_architecture.png'), show_shapes=True)
            print(f"Model architecture saved to {os.path.join(self.model_dir, 'lstm_model_architecture.png')}")
        except Exception as e:
            print(f"Could not save model architecture visualization: {e}")
        
        return model
    
    def train_models(self, csv_path, epochs=EPOCHS, batch_size=BATCH_SIZE):
        """
        Train both LSTM and Random Forest models.
        
        Args:
            csv_path: Path to training data CSV
            epochs: Number of epochs for LSTM training
            batch_size: Batch size for LSTM training
            
        Returns:
            Dictionary with training results
        """
        try:
            print("Starting model training...")
            start_time = time.time()
            
            # Prepare data
            X_train, X_test, y_train, y_test, sequences_train, sequences_test = self.prepare_data(csv_path)
            
            # Train Random Forest model
            print("\nTraining Random Forest model...")
            rf_start_time = time.time()
            self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
            self.rf_model.fit(X_train, y_train)
            rf_train_time = time.time() - rf_start_time
            
            # Evaluate Random Forest
            rf_pred = self.rf_model.predict(X_test)
            rf_proba = self.rf_model.predict_proba(X_test)[:, 1]
            
            rf_metrics = {
                'accuracy': accuracy_score(y_test, rf_pred),
                'precision': precision_score(y_test, rf_pred),
                'recall': recall_score(y_test, rf_pred),
                'f1': f1_score(y_test, rf_pred),
                'roc_auc': roc_auc_score(y_test, rf_proba),
                'training_time': rf_train_time
            }
            
            print(f"Random Forest metrics:")
            for metric, value in rf_metrics.items():
                if metric != 'training_time':
                    print(f"  {metric}: {value:.4f}")
                else:
                    print(f"  {metric}: {value:.2f} seconds")
            
            # Create confusion matrix for Random Forest
            plt.figure(figsize=(8, 6))
            cm = confusion_matrix(y_test, rf_pred)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=['Benign', 'Malicious'], 
                        yticklabels=['Benign', 'Malicious'])
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.title('Random Forest Confusion Matrix')
            plt.savefig(os.path.join(self.model_dir, 'rf_confusion_matrix.png'))
            plt.close()
            
            # Train LSTM model
            print("\nTraining LSTM model...")
            lstm_start_time = time.time()
            self.lstm_model = self.create_lstm_model()
            
            # Callbacks
            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True
            )
            
            model_checkpoint = ModelCheckpoint(
                filepath=os.path.join(self.model_dir, 'lstm_best_model.h5'),
                monitor='val_accuracy',
                save_best_only=True,
                verbose=1
            )
            
            # Train LSTM
            history = self.lstm_model.fit(
                sequences_train, y_train,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=VALIDATION_SPLIT,
                callbacks=[early_stopping, model_checkpoint],
                verbose=1
            )
            lstm_train_time = time.time() - lstm_start_time
            
            # Load best model
            self.lstm_model = tf.keras.models.load_model(os.path.join(self.model_dir, 'lstm_best_model.h5'))
            
            # Evaluate LSTM
            lstm_pred_proba = self.lstm_model.predict(sequences_test)
            lstm_pred = (lstm_pred_proba > 0.5).astype(int).flatten()
            
            lstm_metrics = {
                'accuracy': accuracy_score(y_test, lstm_pred),
                'precision': precision_score(y_test, lstm_pred),
                'recall': recall_score(y_test, lstm_pred),
                'f1': f1_score(y_test, lstm_pred),
                'roc_auc': roc_auc_score(y_test, lstm_pred_proba),
                'training_time': lstm_train_time
            }
            
            print(f"\nLSTM metrics:")
            for metric, value in lstm_metrics.items():
                if metric != 'training_time':
                    print(f"  {metric}: {value:.4f}")
                else:
                    print(f"  {metric}: {value:.2f} seconds")
            
            # Create confusion matrix for LSTM
            plt.figure(figsize=(8, 6))
            cm = confusion_matrix(y_test, lstm_pred)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=['Benign', 'Malicious'], 
                        yticklabels=['Benign', 'Malicious'])
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.title('LSTM Confusion Matrix')
            plt.savefig(os.path.join(self.model_dir, 'lstm_confusion_matrix.png'))
            plt.close()
            
            # Plot training history
            plt.figure(figsize=(12, 5))
            
            plt.subplot(1, 2, 1)
            plt.plot(history.history['accuracy'])
            plt.plot(history.history['val_accuracy'])
            plt.title('Model Accuracy')
            plt.ylabel('Accuracy')
            plt.xlabel('Epoch')
            plt.legend(['Train', 'Validation'], loc='lower right')
            
            plt.subplot(1, 2, 2)
            plt.plot(history.history['loss'])
            plt.plot(history.history['val_loss'])
            plt.title('Model Loss')
            plt.ylabel('Loss')
            plt.xlabel('Epoch')
            plt.legend(['Train', 'Validation'], loc='upper right')
            
            plt.tight_layout()
            plt.savefig(os.path.join(self.model_dir, 'lstm_training_history.png'))
            plt.close()
            
            # Save models
            self.save_models()
            
            # Calculate ensemble predictions
            ensemble_proba = 0.7 * lstm_pred_proba.flatten() + 0.3 * rf_proba
            ensemble_pred = (ensemble_proba > 0.5).astype(int)
            
            ensemble_metrics = {
                'accuracy': accuracy_score(y_test, ensemble_pred),
                'precision': precision_score(y_test, ensemble_pred),
                'recall': recall_score(y_test, ensemble_pred),
                'f1': f1_score(y_test, ensemble_pred),
                'roc_auc': roc_auc_score(y_test, ensemble_proba)
            }
            
            print(f"\nEnsemble metrics:")
            for metric, value in ensemble_metrics.items():
                print(f"  {metric}: {value:.4f}")
            
            # Create confusion matrix for Ensemble
            plt.figure(figsize=(8, 6))
            cm = confusion_matrix(y_test, ensemble_pred)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=['Benign', 'Malicious'], 
                        yticklabels=['Benign', 'Malicious'])
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.title('Ensemble Confusion Matrix')
            plt.savefig(os.path.join(self.model_dir, 'ensemble_confusion_matrix.png'))
            plt.close()
            
            # Compare models
            models = ['Random Forest', 'LSTM', 'Ensemble']
            metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
            
            plt.figure(figsize=(15, 10))
            
            for i, metric in enumerate(metrics):
                plt.subplot(2, 3, i+1)
                values = [rf_metrics[metric], lstm_metrics[metric], ensemble_metrics[metric]]
                bars = plt.bar(models, values, color=['#3498db', '#e74c3c', '#2ecc71'])
                plt.title(f'{metric.upper()}')
                plt.ylim(0.9, 1.0)  # Adjust as needed
                
                # Add value labels on bars
                for bar in bars:
                    height = bar.get_height()
                    plt.text(bar.get_x() + bar.get_width()/2., height,
                            f'{height:.4f}',
                            ha='center', va='bottom', rotation=0)
            
            plt.tight_layout()
            plt.savefig(os.path.join(self.model_dir, 'model_comparison.png'))
            plt.close()
            
            total_time = time.time() - start_time
            print(f"\nTotal training time: {total_time:.2f} seconds")
            
            return {
                'rf_metrics': rf_metrics,
                'lstm_metrics': lstm_metrics,
                'ensemble_metrics': ensemble_metrics,
                'training_history': history.history,
                'total_training_time': total_time
            }
            
        except Exception as e:
            print(f"Error training models: {e}")
            raise
    
    def save_models(self):
        """Save trained models to disk."""
        try:
            # Save LSTM model
            if self.lstm_model:
                lstm_path = os.path.join(self.model_dir, 'lstm_model.h5')
                self.lstm_model.save(lstm_path)
                print(f"LSTM model saved to {lstm_path}")
            
            # Save Random Forest model
            if self.rf_model:
                rf_path = os.path.join(self.model_dir, 'rf_model.pkl')
                joblib.dump(self.rf_model, rf_path)
                print(f"Random Forest model saved to {rf_path}")
            
            # Save tokenizer
            if self.tokenizer:
                tokenizer_path = os.path.join(self.model_dir, 'tokenizer.pkl')
                with open(tokenizer_path, 'wb') as f:
                    pickle.dump(self.tokenizer, f)
                print(f"Tokenizer saved to {tokenizer_path}")
            
            # Save vectorizer
            if self.vectorizer:
                vectorizer_path = os.path.join(self.model_dir, 'vectorizer.pkl')
                joblib.dump(self.vectorizer, vectorizer_path)
                print(f"Vectorizer saved to {vectorizer_path}")
                
            # Create a README file with model information
            readme_path = os.path.join(self.model_dir, 'MODEL_INFO.txt')
            with open(readme_path, 'w') as f:
                f.write("SQL Injection Detection Models\n")
                f.write("============================\n\n")
                f.write(f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Max sequence length: {self.max_len}\n")
                f.write(f"Max words: {self.max_words}\n")
                f.write(f"Embedding dimensions: {self.embedding_dim}\n\n")
                f.write("Files:\n")
                f.write("- lstm_model.h5: LSTM neural network model\n")
                f.write("- rf_model.pkl: Random Forest classifier model\n")
                f.write("- tokenizer.pkl: Text tokenizer for LSTM\n")
                f.write("- vectorizer.pkl: TF-IDF vectorizer for Random Forest\n")
                f.write("- lstm_model_architecture.png: LSTM model architecture visualization\n")
                f.write("- lstm_training_history.png: LSTM training history plot\n")
                f.write("- rf_confusion_matrix.png: Random Forest confusion matrix\n")
                f.write("- lstm_confusion_matrix.png: LSTM confusion matrix\n")
                f.write("- ensemble_confusion_matrix.png: Ensemble model confusion matrix\n")
                f.write("- model_comparison.png: Performance comparison of all models\n\n")
                f.write("Usage Instructions:\n")
                f.write("1. Copy all files to your project's 'models/' directory\n")
                f.write("2. Load models using SQLInjectionMLModel class\n")
                f.write("3. Use predict_vulnerability() method for detection\n")
            
            print(f"Model information saved to {readme_path}")
                
        except Exception as e:
            print(f"Error saving models: {e}")
            raise

# Function to test the trained models
def test_models(model, test_queries):
    """Test the trained models with sample queries."""
    print("\nTesting models with sample queries:")
    print("=" * 50)
    
    for query in test_queries:
        # Prepare for LSTM
        sequence = model.tokenizer.texts_to_sequences([query])
        padded_sequence = pad_sequences(sequence, maxlen=model.max_len)
        lstm_prob = float(model.lstm_model.predict(padded_sequence, verbose=0)[0][0])
        
        # Prepare for Random Forest
        vectorized = model.vectorizer.transform([query]).toarray()
        rf_prob = float(model.rf_model.predict_proba(vectorized)[0][1])
        
        # Ensemble prediction
        ensemble_prob = 0.7 * lstm_prob + 0.3 * rf_prob
        
        print(f"\nQuery: {query}")
        print(f"LSTM probability: {lstm_prob:.4f} ({'Malicious' if lstm_prob > 0.5 else 'Benign'})")
        print(f"RF probability: {rf_prob:.4f} ({'Malicious' if rf_prob > 0.5 else 'Benign'})")
        print(f"Ensemble probability: {ensemble_prob:.4f} ({'Malicious' if ensemble_prob > 0.5 else 'Benign'})")
        print("-" * 50)

# Main execution
if __name__ == "__main__":
    # Set the path to your CSV file in Google Drive
    CSV_PATH = '/content/drive/MyDrive/clean_sql_dataset.csv'
    
    # If the file doesn't exist, provide instructions
    if not os.path.exists(CSV_PATH):
        print(f"CSV file not found at {CSV_PATH}")
        print("\nPlease upload your dataset to Google Drive first:")
        print("1. Upload the SQL injection dataset to your Google Drive")
        print("2. Update the CSV_PATH variable to point to your file")
        print("3. Run this cell again")
    else:
        # Initialize and train models
        model = SQLInjectionMLModel()
        results = model.train_models(CSV_PATH)
        
        # Test with sample queries
        test_queries = [
            "SELECT * FROM users WHERE id = 1",
            "' OR 1=1--",
            "admin' OR '1'='1",
            "SELECT * FROM products WHERE name = 'laptop'",
            "1; DROP TABLE users--",
            "SELECT * FROM users WHERE username = 'john' AND password = 'password'"
        ]
        
        test_models(model, test_queries)
        
        print("\n✅ Training and testing completed successfully!")
        print(f"All models and files saved to: {MODELS_DIR}")
        print("\nTo use these models in your project:")
        print("1. Download all files from this Google Drive folder")
        print("2. Place them in your project's 'models/' directory")
        print("3. The models will be automatically loaded by SQLInjectionMLModel")
