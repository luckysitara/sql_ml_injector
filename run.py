#!/usr/bin/env python3
"""
SQL Injection Testing Tool - Application Entry Point
Professional security testing tool for authorized use only.
"""

import os
import sys
import argparse
import logging
from app import create_app

def setup_logging():
    """Setup application logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('sqli_tester.log')
        ]
    )

def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                SQL Injection Testing Tool                    ║
    ║                                                              ║
    ║  Professional security testing tool for authorized use only  ║
    ║                                                              ║
    ║  Server: http://0.0.0.0:5000                                 ║
    ║  Debug:  False                                               ║
    ║                                                              ║
    ║  📊 Payloads: Loaded from CSV dataset                       ║
    ║  🔄 Use --fetch-payloads to view payload information        ║
    ║                                                              ║
    ║  ⚠️  LEGAL NOTICE: Only use on systems you own or have      ║
    ║     explicit written permission to test.                    ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def train_model_cli(csv_path):
    """Train ML model from command line"""
    try:
        from ml_model import SQLInjectionMLModel
        
        print("🤖 Training Machine Learning Model...")
        print("=" * 60)
        
        if not os.path.exists(csv_path):
            print(f"❌ Error: CSV file not found at {csv_path}")
            sys.exit(1)
        
        ml_model = SQLInjectionMLModel()
        results = ml_model.train_models(csv_path)
        
        print("✅ Model training completed successfully!")
        print()
        print("📊 Training Results:")
        print("-" * 40)
        
        print("LSTM Model:")
        for metric, value in results['lstm_metrics'].items():
            print(f"  {metric.title()}: {value:.4f}")
        
        print()
        print("Random Forest Model:")
        for metric, value in results['rf_metrics'].items():
            print(f"  {metric.title()}: {value:.4f}")
        
        print()
        print("🎯 Models saved and ready for use!")
        
    except Exception as e:
        print(f"❌ Error training model: {e}")
        sys.exit(1)

def fetch_payloads_info():
    """Fetch and display payload information"""
    try:
        from app.injector import SQLInjectionTester
        
        print("🔍 Fetching payload information...")
        print("=" * 60)
        
        tester = SQLInjectionTester()
        stats = tester.get_payload_statistics()
        
        print(f"📊 Total Payloads: {stats['total_payloads']}")
        print(f"📂 Categories: {stats['category_count']}")
        print()
        
        print("📋 Category Breakdown:")
        print("-" * 40)
        for category, count in stats['categories'].items():
            category_name = category.replace('_', ' ').title()
            print(f"  {category_name:.<25} {count:>4}")
        
        print()
        print("🔗 CSV Dataset URL:")
        print("https://hebbkx1anhila5yf.public.blob.vercel-storage.com/mbih-tvKJD7TTjrCGjADXX1qeMMs5vLOFH8.csv")
        print()
        
        # Show sample payloads
        print("🎯 Sample Payloads:")
        print("-" * 40)
        sample_payloads = tester.get_payloads()[:10]
        for i, payload in enumerate(sample_payloads, 1):
            print(f"  {i:2d}. {payload}")
        
        if len(tester.get_payloads()) > 10:
            print(f"  ... and {len(tester.get_payloads()) - 10} more payloads")
        
        print()
        print("✅ Payload information loaded successfully!")
        
    except Exception as e:
        print(f"❌ Error fetching payload information: {e}")
        sys.exit(1)

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description='SQL Injection Testing Tool - Professional security testing for authorized use only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Start the web application
  python run.py --host 0.0.0.0 --port 8080  # Custom host and port
  python run.py --debug                  # Enable debug mode
  python run.py --fetch-payloads         # View payload information

Legal Notice:
  This tool is for authorized security testing only. Only use on systems
  you own or have explicit written permission to test. Unauthorized use
  is illegal and unethical.
        """
    )
    
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind the server to (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind the server to (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    parser.add_argument(
        '--fetch-payloads',
        action='store_true',
        help='Fetch and display payload information without starting the server'
    )
    
    parser.add_argument(
        '--train-model',
        metavar='CSV_PATH',
        help='Train ML model using the specified CSV dataset'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging()
    
    # Handle payload fetching
    if args.fetch_payloads:
        fetch_payloads_info()
        return
    
    if args.train_model:
        train_model_cli(args.train_model)
        return
    
    # Print banner
    print_banner()
    
    try:
        # Create Flask application
        app = create_app()
        
        # Set environment variables
        if args.debug:
            os.environ['FLASK_DEBUG'] = 'True'
            app.config['DEBUG'] = True
        
        # Start the application
        print(f" * Starting SQL Injection Testing Tool")
        print(f" * Environment: {'Development' if args.debug else 'Production'}")
        print(f" * Host: {args.host}")
        print(f" * Port: {args.port}")
        print()
        
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True
        )
        
    except KeyboardInterrupt:
        print("\n\n🛑 Application stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
