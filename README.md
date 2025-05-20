
## Overview

SQL Injection Scanner is a web application designed to detect and analyze SQL injection vulnerabilities in web applications. This version uses a Python backend for the scanning engine and machine learning model, with a Next.js frontend for the user interface.

The application uses advanced machine learning techniques to identify various types of SQL injection vulnerabilities, including error-based, union-based, blind, and time-based injections across multiple database systems.

## Architecture

The application is split into two main components:

1. **Python Backend**:

1. FastAPI web server
2. TensorFlow/Keras ML model for vulnerability detection
3. SQL injection payload generation and analysis
4. Scanning engine



2. **Next.js Frontend**:

1. React-based user interface
2. Form handling and validation
3. Results visualization
4. API communication with the Python backend





## Dependencies

### Backend (Python)

- Python 3.8+
- FastAPI
- TensorFlow 2.x
- scikit-learn
- pandas
- numpy
- requests
- uvicorn (ASGI server)
- python-dotenv


### Frontend (Next.js)

- Node.js 18.x+
- Next.js 14.x
- React 18.x
- shadcn/ui components
- Tailwind CSS
- React Hook Form with Zod


## Installation

### Step 1: Clone the Repository

```shellscript
git clone https://github.com/yourusername/sql-injection-scanner.git
cd sql-injection-scanner
```

### Step 2: Set Up Python Backend

```shellscript
# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 3: Set Up Next.js Frontend

```shellscript
# Navigate to the frontend directory
cd frontend

# Install Node.js dependencies
npm install
# or
pnpm install
```

### Step 4: Set Up Environment Variables

Create a `.env` file in the backend directory:

```plaintext
# Backend settings
HOST=0.0.0.0
PORT=8000
DEBUG=True

# ML model settings
MODEL_PATH=./models/sql_injection_model
```

Create a `.env.local` file in the frontend directory:

```plaintext
# API URL
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Project Structure

```plaintext
sql-injection-scanner/
├── backend/                  # Python backend
│   ├── app/                  # FastAPI application
│   │   ├── api/              # API endpoints
│   │   ├── core/             # Core functionality
│   │   ├── ml/               # Machine learning components
│   │   └── main.py           # FastAPI entry point
│   ├── models/               # Trained ML models
│   ├── data/                 # Training data
│   ├── scripts/              # Utility scripts
│   │   └── train_model.py    # Model training script
│   └── requirements.txt      # Python dependencies
│
├── frontend/                 # Next.js frontend
│   ├── app/                  # Next.js app directory
│   ├── components/           # React components
│   ├── lib/                  # Utility functions
│   └── package.json          # Node.js dependencies
│
└── README.md                 # Project documentation
```

## Backend Implementation

### Key Python Files

#### 1. `backend/app/main.py`

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router

app = FastAPI(title="SQL Injection Scanner API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
```

#### 2. `backend/app/api/routes.py`

```python
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from app.core.scanner import scan_target

router = APIRouter()

class ScanRequest(BaseModel):
    url: HttpUrl
    parameters: Optional[List[str]] = []
    cookies: Optional[List[str]] = []
    headers: Optional[List[str]] = []
    deep_scan: bool = False

@router.post("/scan")
async def scan(request: ScanRequest):
    try:
        results = scan_target(
            url=str(request.url),
            parameters=request.parameters,
            cookies=request.cookies,
            headers=request.headers,
            deep_scan=request.deep_scan
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

#### 3. `backend/app/core/scanner.py`

```python
import requests
from urllib.parse import urlparse, parse_qs
from app.core.payloads import get_payloads
from app.ml.predictor import predict_sql_injection
from app.core.analyzer import analyze_response, generate_mitigations
import time

def scan_target(url, parameters=None, cookies=None, headers=None, deep_scan=False):
    """
    Scan a target URL for SQL injection vulnerabilities
    """
    start_time = time.time()
    
    # Parse URL and extract parameters if none provided
    parsed_url = urlparse(url)
    target_params = parameters or []
    
    if not target_params:
        query_params = parse_qs(parsed_url.query)
        target_params = list(query_params.keys())
    
    # Initialize results
    results = {
        "vulnerabilities": [],
        "mitigations": [],
        "summary": {
            "total_tested": 0,
            "vulnerable_parameters": 0,
            "scan_duration": 0
        }
    }
    
    # Get payloads based on scan depth
    payloads = get_payloads(limit=None if deep_scan else 50)
    
    # Test each parameter
    for param in target_params:
        vulnerabilities = test_parameter(url, param, payloads, cookies, headers)
        
        results["vulnerabilities"].extend(vulnerabilities)
        
        if vulnerabilities:
            results["summary"]["vulnerable_parameters"] += 1
            
        results["summary"]["total_tested"] += 1
    
    # Generate mitigation recommendations
    results["mitigations"] = generate_mitigations(results["vulnerabilities"])
    
    # Calculate scan duration
    results["summary"]["scan_duration"] = time.time() - start_time
    
    return results

def test_parameter(base_url, parameter, payloads, cookies=None, headers=None):
    """
    Test a single parameter with multiple payloads
    """
    vulnerabilities = []
    parsed_url = urlparse(base_url)
    query_params = parse_qs(parsed_url.query)
    
    # Get original parameter value
    original_value = query_params.get(parameter, [""])[0]
    
    # Test each payload
    for payload in payloads:
        try:
            # Create test URL with payload
            test_url = build_test_url(base_url, parameter, payload)
            
            # Send request
            response = send_request(test_url, cookies, headers)
            
            # Analyze response
            analysis = analyze_response(payload, response, parameter)
            
            if analysis["is_vulnerable"]:
                vulnerabilities.append({
                    "type": analysis["type"],
                    "parameter": parameter,
                    "payload": payload,
                    "confidence": analysis["confidence"],
                    "details": analysis["details"],
                    "evidence": analysis["evidence"]
                })
                
                # Stop testing this parameter if vulnerability found (unless deep scan)
                if "deep_scan=true" not in base_url:
                    break
                    
        except Exception as e:
            print(f"Error testing parameter {parameter} with payload {payload}: {e}")
            continue
    
    return vulnerabilities

def build_test_url(base_url, parameter, payload):
    """
    Build a test URL with the payload injected into the parameter
    """
    parsed_url = urlparse(base_url)
    query_params = parse_qs(parsed_url.query)
    
    # Update parameter with payload
    query_params[parameter] = [payload]
    
    # Rebuild query string
    new_query = "&".join(f"{k}={v[0]}" for k, v in query_params.items())
    
    # Rebuild URL
    new_url = parsed_url._replace(query=new_query).geturl()
    
    return new_url

def send_request(url, cookies=None, headers=None):
    """
    Send HTTP request to the target URL
    """
    # Prepare headers
    request_headers = {
        "User-Agent": "SQLGuardian/1.0"
    }
    
    # Add custom headers
    if headers:
        for header in headers:
            if ":" in header:
                name, value = header.split(":", 1)
                request_headers[name.strip()] = value.strip()
    
    # Prepare cookies
    request_cookies = {}
    if cookies:
        for cookie in cookies:
            if "=" in cookie:
                name, value = cookie.split("=", 1)
                request_cookies[name.strip()] = value.strip()
    
    # Send request with timeout
    response = requests.get(
        url, 
        headers=request_headers,
        cookies=request_cookies,
        timeout=10,
        allow_redirects=True
    )
    
    return {
        "status": response.status_code,
        "body": response.text,
        "headers": dict(response.headers)
    }
```

#### 4. `backend/app/ml/predictor.py`

```python
import tensorflow as tf
import numpy as np
import os
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Global variables
model = None
tokenizer = None
MAX_SEQUENCE_LENGTH = 100

def load_model():
    """
    Load the trained TensorFlow model and tokenizer
    """
    global model, tokenizer
    
    if model is not None:
        return
    
    model_path = os.environ.get("MODEL_PATH", "./models/sql_injection_model")
    
    # Load model
    model = tf.keras.models.load_model(f"{model_path}/model.h5")
    
    # Load tokenizer
    with open(f"{model_path}/tokenizer.json", 'r') as f:
        import json
        tokenizer_config = json.load(f)
        
    tokenizer = Tokenizer()
    tokenizer.word_index = tokenizer_config["word_index"]
    
    print("Model and tokenizer loaded successfully")

def predict_sql_injection(query):
    """
    Predict if a query is a SQL injection
    """
    global model, tokenizer
    
    if model is None or tokenizer is None:
        load_model()
    
    # Tokenize and pad the query
    sequences = tokenizer.texts_to_sequences([query])
    padded_sequence = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH)
    
    # Make prediction
    prediction = model.predict(padded_sequence)[0][0]
    
    return {
        "is_sql_injection": bool(prediction > 0.5),
        "confidence": float(prediction * 100)
    }
```

#### 5. `backend/scripts/train_model.py`

```python
import tensorflow as tf
import numpy as np
import pandas as pd
import os
import json
from sklearn.model_selection import train_test_split
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Constants
MAX_SEQUENCE_LENGTH = 100
MAX_NUM_WORDS = 20000
EMBEDDING_DIM = 100
VALIDATION_SPLIT = 0.2
TEST_SPLIT = 0.1
BATCH_SIZE = 64
EPOCHS = 10

def load_data(data_path):
    """
    Load and preprocess the dataset
    """
    print(f"Loading data from {data_path}")
    
    # Load data from CSV
    df = pd.read_csv(data_path)
    
    # Extract features and labels
    queries = df['query'].values
    labels = df['is_sql_injection'].values
    
    return queries, labels

def create_model(max_words, embedding_dim, max_seq_length):
    """
    Create the neural network model
    """
    model = tf.keras.Sequential([
        tf.keras.layers.Embedding(max_words + 1, embedding_dim, input_length=max_seq_length, mask_zero=True),
        tf.keras.layers.SpatialDropout1D(0.3),
        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(128, return_sequences=True)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.5),
        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(64, return_sequences=False)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.5),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dropout(0.5),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    
    # Compile the model
    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    return model

def train_model():
    """
    Train the SQL injection detection model
    """
    # Create output directory
    output_dir = "./models/sql_injection_model"
    os.makedirs(output_dir, exist_ok=True)
    
    # Load data
    data_path = "./data/sql_injection_dataset.csv"
    queries, labels = load_data(data_path)
    
    # Split data into training, validation, and test sets
    X_train, X_temp, y_train, y_temp = train_test_split(
        queries, labels, test_size=VALIDATION_SPLIT + TEST_SPLIT, random_state=42
    )
    
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=TEST_SPLIT/(VALIDATION_SPLIT + TEST_SPLIT), random_state=42
    )
    
    # Create and fit tokenizer
    tokenizer = Tokenizer(num_words=MAX_NUM_WORDS)
    tokenizer.fit_on_texts(X_train)
    
    # Convert text to sequences
    X_train_seq = tokenizer.texts_to_sequences(X_train)
    X_val_seq = tokenizer.texts_to_sequences(X_val)
    X_test_seq = tokenizer.texts_to_sequences(X_test)
    
    # Pad sequences
    X_train_pad = pad_sequences(X_train_seq, maxlen=MAX_SEQUENCE_LENGTH)
    X_val_pad = pad_sequences(X_val_seq, maxlen=MAX_SEQUENCE_LENGTH)
    X_test_pad = pad_sequences(X_test_seq, maxlen=MAX_SEQUENCE_LENGTH)
    
    # Create model
    model = create_model(MAX_NUM_WORDS, EMBEDDING_DIM, MAX_SEQUENCE_LENGTH)
    model.summary()
    
    # Define callbacks
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=3,
            restore_best_weights=True
        ),
        tf.keras.callbacks.ModelCheckpoint(
            filepath=f"{output_dir}/model_checkpoint.h5",
            monitor='val_loss',
            save_best_only=True
        )
    ]
    
    # Train the model
    history = model.fit(
        X_train_pad, y_train,
        validation_data=(X_val_pad, y_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=callbacks
    )
    
    # Evaluate the model
    loss, accuracy = model.evaluate(X_test_pad, y_test)
    print(f"Test Loss: {loss:.4f}")
    print(f"Test Accuracy: {accuracy:.4f}")
    
    # Calculate precision, recall, and F1 score
    y_pred = (model.predict(X_test_pad) > 0.5).astype(int)
    
    from sklearn.metrics import precision_score, recall_score, f1_score
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    # Save evaluation results
    evaluation = {
        "loss": float(loss),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1)
    }
    
    with open(f"{output_dir}/evaluation.json", 'w') as f:
        json.dump(evaluation, f, indent=2)
    
    # Save the model
    model.save(f"{output_dir}/model.h5")
    
    # Save the tokenizer
    tokenizer_config = {
        "word_index": tokenizer.word_index,
        "num_words": MAX_NUM_WORDS
    }
    
    with open(f"{output_dir}/tokenizer.json", 'w') as f:
        json.dump(tokenizer_config, f)
    
    print(f"Model and tokenizer saved to {output_dir}")

if __name__ == "__main__":
    train_model()
```

### Python Requirements

Create a `requirements.txt` file in the backend directory:

```plaintext
fastapi==0.104.1
uvicorn==0.24.0
tensorflow==2.14.0
scikit-learn==1.3.2
pandas==2.1.3
numpy==1.26.1
requests==2.31.0
python-dotenv==1.0.0
pydantic==2.4.2
```

## Frontend Implementation

The frontend implementation remains largely the same as in the original project, with the main difference being the API endpoint URL pointing to the Python backend.

### Update API Call in `frontend/components/scanner-form.tsx`

```typescript
// Handle form submission
const onSubmit = async (values: FormValues) => {
  setIsScanning(true);
  setScanResults(null);
  setError(null);

  try {
    // Parse the string inputs into arrays
    const parameters = values.parameters ? values.parameters.split("\n").filter(Boolean) : [];
    const cookies = values.cookies ? values.cookies.split("\n").filter(Boolean) : [];
    const headers = values.headers ? values.headers.split("\n").filter(Boolean) : [];

    console.log("Starting scan for URL:", values.url);

    // Update the API endpoint to point to the Python backend
    const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: values.url,
        parameters,
        cookies,
        headers,
        deep_scan: values.deepScan,
      }),
    });

    // Rest of the function remains the same
    // ...
  }
};
```

## Running the Application

### Step 1: Start the Python Backend

```shellscript
# Navigate to the backend directory
cd backend

# Activate the virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Start the FastAPI server
python -m app.main
```

The backend API will be available at [http://localhost:8000](http://localhost:8000).

### Step 2: Start the Next.js Frontend

```shellscript
# Navigate to the frontend directory
cd frontend

# Start the development server
npm run dev
# or
pnpm dev
```

The frontend will be available at [http://localhost:3000](http://localhost:3000).

## Training the ML Model

To train the machine learning model:

```shellscript
# Navigate to the backend directory
cd backend

# Activate the virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run the training script
python -m scripts.train_model
```

This will:

1. Load the SQL injection dataset
2. Preprocess the data
3. Train a bidirectional LSTM model
4. Evaluate the model
5. Save the model and tokenizer to the `models/sql_injection_model` directory


## Creating a Dataset

If you don't have a dataset, you can create a synthetic one:

```python
# backend/scripts/create_dataset.py
import pandas as pd
import numpy as np
import random
import string
from sklearn.model_selection import train_test_split

def generate_normal_query():
    """Generate a normal SQL query"""
    tables = ['users', 'products', 'orders', 'customers', 'categories']
    columns = ['id', 'name', 'email', 'price', 'quantity', 'date', 'status']
    conditions = ['=', '>', '<', '>=', '<=', 'LIKE', 'IN', 'BETWEEN']
    
    table = random.choice(tables)
    column = random.choice(columns)
    condition = random.choice(conditions)
    
    if condition == '=':
        value = f"'{random.choice(string.ascii_lowercase)}{random.randint(1, 100)}'"
        query = f"SELECT * FROM {table} WHERE {column} = {value}"
    elif condition == 'LIKE':
        value = f"'%{random.choice(string.ascii_lowercase)}%'"
        query = f"SELECT * FROM {table} WHERE {column} LIKE {value}"
    elif condition == 'IN':
        values = [f"'{random.choice(string.ascii_lowercase)}{random.randint(1, 100)}'" for _ in range(3)]
        query = f"SELECT * FROM {table} WHERE {column} IN ({', '.join(values)})"
    elif condition == 'BETWEEN':
        value1 = random.randint(1, 50)
        value2 = random.randint(51, 100)
        query = f"SELECT * FROM {table} WHERE {column} BETWEEN {value1} AND {value2}"
    else:
        value = random.randint(1, 100)
        query = f"SELECT * FROM {table} WHERE {column} {condition} {value}"
    
    return query

def generate_sql_injection():
    """Generate a SQL injection payload"""
    normal_query = generate_normal_query()
    
    # SQL injection patterns
    injections = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users--",
        "' OR '1'='1' LIMIT 1; --",
        "admin'--",
        "1' OR SLEEP(5)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1 UNION SELECT null, username, password FROM users--",
        "'; exec xp_cmdshell('net user');--",
    ]
    
    # Choose a random injection pattern
    injection = random.choice(injections)
    
    # Insert the injection at a random position
    parts = normal_query.split("'")
    if len(parts) > 1:
        # Insert after a quote
        position = random.randint(1, len(parts) - 1)
        parts[position] = injection[1:] + parts[position]
        return "'".join(parts)
    else:
        # Append to the query
        return normal_query + " " + injection

def create_dataset(size=10000, output_file='./data/sql_injection_dataset.csv'):
    """Create a synthetic SQL injection dataset"""
    # Generate normal queries (60% of dataset)
    normal_count = int(size * 0.6)
    normal_queries = [generate_normal_query() for _ in range(normal_count)]
    normal_labels = [0] * normal_count
    
    # Generate SQL injection queries (40% of dataset)
    injection_count = size - normal_count
    injection_queries = [generate_sql_injection() for _ in range(injection_count)]
    injection_labels = [1] * injection_count
    
    # Combine and shuffle
    queries = normal_queries + injection_queries
    labels = normal_labels + injection_labels
    
    # Create DataFrame
    df = pd.DataFrame({
        'query': queries,
        'is_sql_injection': labels
    })
    
    # Shuffle the dataset
    df = df.sample(frac=1).reset_index(drop=True)
    
    # Save to CSV
    import os
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    
    print(f"Dataset created with {size} samples and saved to {output_file}")
    print(f"Normal queries: {normal_count}")
    print(f"SQL injection queries: {injection_count}")

if __name__ == "__main__":
    create_dataset()
```

Run the script to create the dataset:

```shellscript
python -m scripts.create_dataset
```

## Deployment

### Backend Deployment

You can deploy the Python backend to various platforms:

#### Option 1: Docker

Create a `Dockerfile` in the backend directory:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run the Docker container:

```shellscript
docker build -t sql-injection-scanner-backend .
docker run -p 8000:8000 sql-injection-scanner-backend
```

#### Option 2: Cloud Platforms

The Python backend can be deployed to platforms like:

- Heroku
- AWS Elastic Beanstalk
- Google Cloud Run
- Azure App Service


### Frontend Deployment

The Next.js frontend can be deployed to:

- Vercel (recommended)
- Netlify
- AWS Amplify
- GitHub Pages


## Conclusion

This documentation provides a comprehensive guide to setting up and running the SQL Injection Scanner with a Python backend and Next.js frontend. The Python backend offers powerful machine learning capabilities for detecting SQL injection vulnerabilities, while the Next.js frontend provides a user-friendly interface for interacting with the scanner.

By following the installation and usage instructions, you can effectively scan web applications for SQL injection vulnerabilities and receive detailed reports with mitigation recommendations.

## Disclaimer

This tool is for educational and security testing purposes only. Always obtain proper authorization before scanning any website. The developers are not responsible for any misuse or damage caused by this tool.
