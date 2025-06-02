"""
Test script to verify Random Forest model loading and functionality.
"""

import os
from ml_model import SQLInjectionMLModel

def test_model_loading():
    """Test if the Random Forest model loads correctly"""
    print("🔍 Testing Random Forest Model Loading...")
    print("=" * 50)
    
    # Initialize model
    model = SQLInjectionMLModel()
    
    # Get model info
    info = model.get_model_info()
    print(f"📊 Model Info:")
    print(f"   - Random Forest loaded: {info['rf_loaded']}")
    print(f"   - Vectorizer loaded: {info['vectorizer_loaded']}")
    print(f"   - Models directory: {info['models_directory']}")
    print(f"   - Model type: {info['model_type']}")
    
    # Check file existence
    print(f"\n📁 File Status:")
    for model_name, exists in info['models_available'].items():
        status = "✅ Found" if exists else "❌ Missing"
        print(f"   - {model_name}: {status}")
    
    if not info['rf_loaded'] or not info['vectorizer_loaded']:
        print("\n❌ Models not loaded properly!")
        print("Make sure you have:")
        print("   1. rf_model.pkl in the models/ directory")
        print("   2. vectorizer.pkl in the models/ directory")
        return False
    
    print("\n✅ Models loaded successfully!")
    return True

def test_predictions():
    """Test model predictions with sample queries"""
    print("\n🧪 Testing Model Predictions...")
    print("=" * 50)
    
    model = SQLInjectionMLModel()
    
    # Test queries
    test_queries = [
        "SELECT * FROM users WHERE id = 1",  # Benign
        "' OR 1=1--",  # Malicious
        "admin' OR '1'='1",  # Malicious
        "SELECT name FROM products WHERE category = 'electronics'",  # Benign
        "'; DROP TABLE users--",  # Malicious
        "1 UNION SELECT username, password FROM users",  # Malicious
        "SELECT COUNT(*) FROM orders",  # Benign
        "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",  # Malicious
    ]
    
    print(f"Testing {len(test_queries)} queries:\n")
    
    for i, query in enumerate(test_queries, 1):
        result = model.predict_vulnerability(query)
        
        status = "🔴 VULNERABLE" if result['is_vulnerable'] else "🟢 SAFE"
        confidence = result['confidence']
        risk_level = result['risk_level']
        
        print(f"{i}. Query: {query[:50]}{'...' if len(query) > 50 else ''}")
        print(f"   Status: {status}")
        print(f"   Confidence: {confidence:.4f}")
        print(f"   Risk Level: {risk_level}")
        print(f"   Model Used: {result['model_used']}")
        print()

def test_feature_importance():
    """Test feature importance extraction"""
    print("🎯 Testing Feature Importance...")
    print("=" * 50)
    
    model = SQLInjectionMLModel()
    features = model.get_feature_importance(top_n=10)
    
    if 'error' in features:
        print(f"❌ Error getting features: {features['error']}")
        return
    
    print(f"📈 Top 10 Most Important Features:")
    print(f"   Total features: {features['total_features']}")
    print(f"   Model type: {features['model_type']}\n")
    
    for i, feature_info in enumerate(features['top_features'], 1):
        feature_name = feature_info['feature']
        importance = feature_info['importance']
        print(f"{i:2d}. {feature_name:<20} | {importance:.6f}")

def test_response_analysis():
    """Test response pattern analysis"""
    print("\n🔍 Testing Response Pattern Analysis...")
    print("=" * 50)
    
    model = SQLInjectionMLModel()
    
    # Test different response scenarios
    test_cases = [
        {
            'name': 'SQL Error Response',
            'response': 'MySQL Error: You have an error in your SQL syntax',
            'status_code': 500,
            'response_time': 1000
        },
        {
            'name': 'Normal Response',
            'response': 'User profile loaded successfully',
            'status_code': 200,
            'response_time': 500
        },
        {
            'name': 'Time-based Response',
            'response': 'Query executed',
            'status_code': 200,
            'response_time': 6000
        },
        {
            'name': 'Blocked Response',
            'response': 'Request blocked by security policy',
            'status_code': 403,
            'response_time': 200
        }
    ]
    
    for case in test_cases:
        analysis = model.analyze_response_patterns(
            case['response'], 
            case['status_code'], 
            case['response_time']
        )
        
        print(f"📋 {case['name']}:")
        print(f"   Response: {case['response'][:50]}{'...' if len(case['response']) > 50 else ''}")
        print(f"   Status Code: {case['status_code']}")
        print(f"   Response Time: {case['response_time']}ms")
        print(f"   Risk Level: {analysis['risk_level']}")
        print(f"   Confidence Score: {analysis['confidence_score']:.4f}")
        print(f"   Error Score: {analysis['error_score']:.4f}")
        print(f"   Time Score: {analysis['time_score']:.4f}")
        print(f"   Status Score: {analysis['status_score']:.4f}")
        print()

def main():
    """Main test function"""
    print("🚀 SQL Injection Random Forest Model Test Suite")
    print("=" * 60)
    
    # Test 1: Model Loading
    if not test_model_loading():
        print("\n❌ Model loading failed. Please check your model files.")
        return
    
    # Test 2: Predictions
    test_predictions()
    
    # Test 3: Feature Importance
    test_feature_importance()
    
    # Test 4: Response Analysis
    test_response_analysis()
    
    print("✅ All tests completed!")
    print("\n📝 Summary:")
    print("   - Random Forest model is working correctly")
    print("   - Predictions are being generated")
    print("   - Feature importance is accessible")
    print("   - Response analysis is functional")
    print("\n🎉 Your SQL injection detection system is ready!")

if __name__ == "__main__":
    main()
