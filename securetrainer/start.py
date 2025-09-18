#!/usr/bin/env python3
"""
SecureTrainer Startup Script
Simple script to start the SecureTrainer application with proper configuration.
"""

import os
import sys
from pathlib import Path

def check_environment():
    """Check if the environment is properly configured."""
    print("🔍 Checking environment...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Check if .env file exists
    env_file = Path('.env')
    if not env_file.exists():
        print("⚠️  .env file not found. Creating template...")
        create_env_template()
        print("📝 Please configure your .env file with your credentials")
        return False
    
    print("✅ .env file found")
    
    # Check required packages
    try:
        import flask
        import flask_mail
        import bcrypt
        import qrcode
        import pymongo
        import flask_cors
        print("✅ All required packages are installed")
    except ImportError as e:
        print(f"❌ Missing package: {e}")
        print("💡 Run: pip install -r requirements.txt")
        return False
    
    return True

def create_env_template():
    """Create a template .env file."""
    env_template = """# SecureTrainer Environment Configuration

# Security
SECRET_KEY=your-super-secret-key-here-change-this

# Email Configuration (Gmail Example)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Database
MONGO_URI=mongodb://localhost:27017/securetrainer

# Development Settings
FLASK_ENV=development
DEBUG=True
PORT=5000
"""
    
    with open('.env', 'w') as f:
        f.write(env_template)

def start_application():
    """Start the SecureTrainer application."""
    print("\n🚀 Starting SecureTrainer...")
    
    try:
        # Import the app from securetrainer.py
        from securetrainer import app
        
        # Get configuration
        port = int(os.environ.get('PORT', 5000))
        debug = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG', 'False') == 'True'
        
        print(f"📍 Port: {port}")
        print(f"🔧 Debug: {debug}")
        print(f"🌐 URL: http://localhost:{port}")
        print("\n🎯 SecureTrainer is now running!")
        print("📱 Open your browser and navigate to the URL above")
        print("⏹️  Press Ctrl+C to stop the application")
        print("\n" + "="*50)
        
        # Run the application
        app.run(host='0.0.0.0', port=port, debug=debug)
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all required packages are installed")
        print("💡 Run: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        print("💡 Check your configuration and try again")
        return False
    
    return True

def main():
    """Main function."""
    print("🛡️ SecureTrainer - Cybersecurity Training Platform")
    print("=" * 50)
    
    # Check environment
    if not check_environment():
        print("\n❌ Environment check failed. Please fix the issues above.")
        return 1
    
    print("\n✅ Environment check passed!")
    
    # Start application
    try:
        start_application()
    except KeyboardInterrupt:
        print("\n\n👋 SecureTrainer stopped by user")
        return 0
    except Exception as e:
        print(f"\n❌ Application error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
