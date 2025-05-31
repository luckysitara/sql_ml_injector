# test_models.py
from ml_model import SQLInjectionMLModel

def test_model_loading():
    print("Testing model loading...")
    model = SQLInjectionMLModel()
    model_info = model.get_model_info()
    print(f"Model info: {model_info}")
    
    if model_info['lstm_loaded'] and model_info['rf_loaded']:
        print("✅ Models loaded successfully!")
        
        # Test a sample query
        test_query = "' OR 1=1--"
        result = model.predict_vulnerability(test_query)
        print(f"\nTest query: {test_query}")
        print(f"Prediction: {'Vulnerable' if result['is_vulnerable'] else 'Safe'}")
        print(f"Confidence: {result['confidence']:.4f}")
    else:
        print("❌ Model loading failed!")

if __name__ == "__main__":
    test_model_loading()
