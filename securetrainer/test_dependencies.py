#!/usr/bin/env python3
"""
Test Dependencies Script
This script tests all the imports and dependencies for SecureTrainer.
"""

import sys
import os

def test_basic_imports():
    """Test basic Python imports."""
    print("🔍 Testing basic imports...")
    
    try:
        import flask
        print(f"✅ Flask {flask.__version__}")
    except ImportError as e:
        print(f"❌ Flask: {e}")
        return False
    
    try:
        import flask_mail
        print("✅ Flask-Mail")
    except ImportError as e:
        print(f"❌ Flask-Mail: {e}")
        return False
    
    try:
        import flask_cors
        print("✅ Flask-CORS")
    except ImportError as e:
        print(f"❌ Flask-CORS: {e}")
        return False
    
    try:
        import bcrypt
        print("✅ bcrypt")
    except ImportError as e:
        print(f"❌ bcrypt: {e}")
        return False
    
    try:
        import qrcode
        print("✅ qrcode")
    except ImportError as e:
        print(f"❌ qrcode: {e}")
        return False
    
    try:
        import pymongo
        print("✅ pymongo")
    except ImportError as e:
        print(f"❌ pymongo: {e}")
        return False
    
    try:
        import PIL
        print("✅ Pillow (PIL)")
    except ImportError as e:
        print(f"❌ Pillow: {e}")
        return False
    
    try:
        import joblib
        print("✅ joblib")
    except ImportError as e:
        print(f"❌ joblib: {e}")
        return False
    
    try:
        import sklearn
        print("✅ scikit-learn")
    except ImportError as e:
        print(f"❌ scikit-learn: {e}")
        return False
    
    try:
        import pandas
        print("✅ pandas")
    except ImportError as e:
        print(f"❌ pandas: {e}")
        return False
    
    try:
        import numpy
        print("✅ numpy")
    except ImportError as e:
        print(f"❌ numpy: {e}")
        return False
    
    return True

def test_app_imports():
    """Test SecureTrainer app imports."""
    print("\n🔍 Testing SecureTrainer imports...")
    
    try:
        import app.models.user_model
        print("✅ User model")
    except ImportError as e:
        print(f"❌ User model: {e}")
        return False
    
    try:
        import app.models.challenge_model
        print("✅ Challenge model")
    except ImportError as e:
        print(f"❌ Challenge model: {e}")
        return False
    
    try:
        from app.utils.qr import QRCodeManager
        print("✅ QR utility")
    except ImportError as e:
        print(f"❌ QR utility: {e}")
        return False
    
    try:
        from app.utils.email import EmailManager
        print("✅ Email utility")
    except ImportError as e:
        print(f"❌ Email utility: {e}")
        return False
    
    try:
        import app.routes.ai_model
        print("✅ AI model routes")
    except ImportError as e:
        print(f"⚠️ AI model routes: {e}")
        print("   This is not critical for basic functionality")
    
    return True

def test_app_creation():
    """Test if the Flask app can be created."""
    print("\n🔍 Testing Flask app creation...")
    
    try:
        from securetrainer import app
        print("✅ Flask app imported successfully")
        print(f"✅ App name: {app.name}")
        print(f"✅ App config: {app.config.get('ENV', 'production')}")
        return True
    except Exception as e:
        print(f"❌ Flask app creation failed: {e}")
        return False

def main():
    """Main function."""
    print("🛡️ SecureTrainer Dependency Test")
    print("=" * 40)
    
    # Test basic imports
    if not test_basic_imports():
        print("\n❌ Basic imports failed. Please install missing packages:")
        print("   pip install -r requirements.txt")
        return 1
    
    # Test app imports
    if not test_app_imports():
        print("\n❌ App imports failed. Check your project structure.")
        return 1
    
    # Test app creation
    if not test_app_creation():
        print("\n❌ App creation failed. Check your configuration.")
        return 1
    
    print("\n🎉 All tests passed! SecureTrainer is ready to run.")
    print("\n📝 Next steps:")
    print("1. Ensure MongoDB is running")
    print("2. Run: python start.py")
    print("3. Open: http://localhost:5000")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
