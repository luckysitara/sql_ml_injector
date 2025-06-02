# SQL Injection Detection Models

This directory contains the pre-trained Random Forest model files for SQL injection detection.

## Required Files

Make sure you have the following files in this directory:

- `rf_model.pkl` - Random Forest classifier model
- `vectorizer.pkl` - TF-IDF vectorizer for text preprocessing

## File Descriptions

### rf_model.pkl
- **Type**: Random Forest Classifier
- **Purpose**: Classifies SQL queries as malicious or benign
- **Features**: Uses TF-IDF vectorized text features
- **Training**: Trained on a large dataset of SQL injection payloads

### vectorizer.pkl
- **Type**: TF-IDF Vectorizer
- **Purpose**: Converts text queries into numerical features
- **Configuration**: 
  - Max features: 5000
  - N-grams: 1-3
  - Stop words: English
  - Min/Max document frequency optimized

## Usage

The models are automatically loaded by the `SQLInjectionMLModel` class when the application starts. No manual loading is required.

## Model Performance

The Random Forest model provides:
- High accuracy in detecting SQL injection attempts
- Fast prediction times suitable for real-time analysis
- Interpretable feature importance for understanding detection logic
- Risk level classification (HIGH/MEDIUM/LOW/MINIMAL)

## Troubleshooting

If models fail to load:

1. **Check file existence**: Ensure both `.pkl` files are in this directory
2. **Check file permissions**: Make sure files are readable
3. **Check dependencies**: Ensure `scikit-learn` and `joblib` are installed
4. **Check file integrity**: Re-download files if they appear corrupted

## Model Information

- **Algorithm**: Random Forest with optimized hyperparameters
- **Input**: Text-based SQL queries
- **Output**: Binary classification (malicious/benign) with confidence scores
- **Features**: TF-IDF vectorized n-grams (1-3) with feature selection
- **Risk Assessment**: Automatic risk level assignment based on confidence scores
