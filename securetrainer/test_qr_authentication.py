#!/usr/bin/env python3
"""
Test QR Code Authentication System
Tests all aspects of QR code generation, validation, and login flow
"""

import os
import sys
import json
import requests
import tempfile
from datetime import datetime, timedelta
from PIL import Image
import qrcode
import io

# Add the parent directory to sys.path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.utils.qr import QRCodeManager
from app.models.user_model import get_db
from pymongo import MongoClient

# Test configuration
TEST_SERVER_URL = "http://localhost:5000"
TEST_EMAIL = "test@example.com"
TEST_USER_DATA = {
    "first_name": "Test",
    "last_name": "User",
    "username": "testuser_qr",
    "email": TEST_EMAIL,
    "password": "testpass123",
    "company": "Test Company",
    "department": "IT"
}

class QRAuthenticationTester:
    def __init__(self):
        self.qr_manager = QRCodeManager()
        self.test_user_id = None
        self.test_qr_data = None
        self.session = requests.Session()
        
    def setup_test_user(self):
        """Create a test user for QR authentication testing."""
        print("🔧 Setting up test user...")
        
        try:
            # Connect to database
            mongo_client = MongoClient('mongodb://localhost:27017/securetrainer')
            db = mongo_client.securetrainer
            
            # Remove existing test user
            db.users.delete_many({"username": TEST_USER_DATA["username"]})
            
            # Create new test user
            import bcrypt
            user_data = TEST_USER_DATA.copy()
            user_data['password'] = bcrypt.hashpw(TEST_USER_DATA['password'].encode('utf-8'), bcrypt.gensalt())
            user_data['level'] = 1
            user_data['score'] = 0
            user_data['role'] = 'Trainee'
            user_data['created_at'] = datetime.now()
            user_data['last_login'] = None
            user_data['challenges_completed'] = []
            user_data['achievements'] = []
            
            result = db.users.insert_one(user_data)
            self.test_user_id = str(result.inserted_id)
            
            print(f"✅ Test user created with ID: {self.test_user_id}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to create test user: {e}")
            return False
    
    def generate_test_qr(self):
        """Generate a QR code for the test user."""
        print("🔧 Generating test QR code...")
        
        try:
            self.test_qr_data = self.qr_manager.generate_qr_code(
                self.test_user_id, 
                TEST_EMAIL,
                expires_in_hours=24
            )
            
            print(f"✅ QR code generated successfully")
            print(f"   Token: {self.test_qr_data['token']}")
            print(f"   Expires: {self.test_qr_data['expires']}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to generate QR code: {e}")
            return False
    
    def test_qr_validation(self):
        """Test QR code validation functionality."""
        print("🧪 Testing QR code validation...")
        
        try:
            # Test valid QR code
            qr_data_json = json.dumps(self.test_qr_data['qr_data'])
            is_valid, result = self.qr_manager.validate_qr_code(qr_data_json)
            
            if is_valid:
                print("✅ QR code validation: PASSED")
                print(f"   User ID: {result['user_id']}")
                print(f"   Token: {result['token']}")
                return True
            else:
                print(f"❌ QR code validation failed: {result}")
                return False
                
        except Exception as e:
            print(f"❌ QR validation test error: {e}")
            return False
    
    def test_file_upload_authentication(self):
        """Test QR code authentication via file upload."""
        print("🧪 Testing file upload authentication...")
        
        try:
            # Create QR code image in memory
            qr_data_json = json.dumps(self.test_qr_data['qr_data'])
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(qr_data_json)
            qr.make(fit=True)
            
            # Generate image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
                img.save(temp_file.name)
                temp_file_path = temp_file.name
            
            try:
                # Test file upload login
                with open(temp_file_path, 'rb') as img_file:
                    files = {'qr_image': ('test_qr.png', img_file, 'image/png')}
                    response = self.session.post(f"{TEST_SERVER_URL}/api/auth/login", files=files)
                
                print(f"   Response status: {response.status_code}")
                print(f"   Response headers: {dict(response.headers)}")
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        print("✅ File upload authentication: PASSED")
                        print(f"   User: {data.get('user', {}).get('username')}")
                        return True
                    else:
                        print(f"❌ File upload authentication failed: {data.get('message')}")
                        return False
                else:
                    print(f"❌ File upload authentication failed with status {response.status_code}")
                    print(f"   Response: {response.text}")
                    return False
                    
            finally:
                # Clean up temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                    
        except Exception as e:
            print(f"❌ File upload test error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_camera_authentication(self):
        """Test QR code authentication via camera data."""
        print("🧪 Testing camera authentication...")
        
        try:
            # Simulate camera QR data
            qr_data_json = json.dumps(self.test_qr_data['qr_data'])
            
            # Test camera login
            payload = {'qr_data': qr_data_json}
            headers = {'Content-Type': 'application/json'}
            response = self.session.post(f"{TEST_SERVER_URL}/api/auth/login", json=payload, headers=headers)
            
            print(f"   Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    print("✅ Camera authentication: PASSED")
                    print(f"   User: {data.get('user', {}).get('username')}")
                    return True
                else:
                    print(f"❌ Camera authentication failed: {data.get('message')}")
                    return False
            else:
                print(f"❌ Camera authentication failed with status {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Camera test error: {e}")
            return False
    
    def test_expired_qr(self):
        """Test behavior with expired QR code."""
        print("🧪 Testing expired QR code...")
        
        try:
            # Create expired QR data
            expired_qr_data = self.test_qr_data['qr_data'].copy()
            expired_qr_data['expires'] = (datetime.now() - timedelta(hours=1)).isoformat()
            
            # Test with expired QR
            qr_data_json = json.dumps(expired_qr_data)
            is_valid, result = self.qr_manager.validate_qr_code(qr_data_json)
            
            if not is_valid and "expired" in result.lower():
                print("✅ Expired QR detection: PASSED")
                return True
            else:
                print(f"❌ Expired QR should be rejected: {result}")
                return False
                
        except Exception as e:
            print(f"❌ Expired QR test error: {e}")
            return False
    
    def test_invalid_qr(self):
        """Test behavior with invalid QR code."""
        print("🧪 Testing invalid QR code...")
        
        try:
            # Test with invalid JSON
            invalid_qr = "invalid_qr_data"
            is_valid, result = self.qr_manager.validate_qr_code(invalid_qr)
            
            if not is_valid:
                print("✅ Invalid QR detection: PASSED")
                return True
            else:
                print(f"❌ Invalid QR should be rejected")
                return False
                
        except Exception as e:
            print(f"❌ Invalid QR test error: {e}")
            return False
    
    def test_dashboard_access(self):
        """Test dashboard access after successful login."""
        print("🧪 Testing dashboard access...")
        
        try:
            response = self.session.get(f"{TEST_SERVER_URL}/dashboard")
            
            if response.status_code == 200:
                print("✅ Dashboard access: PASSED")
                return True
            else:
                print(f"❌ Dashboard access failed with status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Dashboard test error: {e}")
            return False
    
    def cleanup(self):
        """Clean up test data."""
        print("🧹 Cleaning up test data...")
        
        try:
            # Remove test user
            mongo_client = MongoClient('mongodb://localhost:27017/securetrainer')
            db = mongo_client.securetrainer
            db.users.delete_many({"username": TEST_USER_DATA["username"]})
            
            # Remove QR code files
            if self.test_qr_data:
                qr_file = os.path.join(self.qr_manager.storage_path, 
                                     f"{self.test_qr_data['token']}_{self.test_user_id}.png")
                if os.path.exists(qr_file):
                    os.unlink(qr_file)
            
            print("✅ Cleanup completed")
            
        except Exception as e:
            print(f"⚠️ Cleanup error: {e}")
    
    def run_all_tests(self):
        """Run all QR authentication tests."""
        print("🚀 Starting QR Authentication Tests")
        print("=" * 50)
        
        tests = [
            ("Setup Test User", self.setup_test_user),
            ("Generate QR Code", self.generate_test_qr),
            ("QR Validation", self.test_qr_validation),
            ("File Upload Auth", self.test_file_upload_authentication),
            ("Camera Auth", self.test_camera_authentication),
            ("Expired QR", self.test_expired_qr),
            ("Invalid QR", self.test_invalid_qr),
            ("Dashboard Access", self.test_dashboard_access),
        ]
        
        results = []
        
        for test_name, test_func in tests:
            print(f"\n📋 Running: {test_name}")
            try:
                result = test_func()
                results.append((test_name, result))
            except Exception as e:
                print(f"💥 {test_name} crashed: {e}")
                results.append((test_name, False))
        
        # Print summary
        print("\n" + "=" * 50)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 50)
        
        passed = 0
        total = len(results)
        
        for test_name, result in results:
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"{test_name:<20} {status}")
            if result:
                passed += 1
        
        print(f"\nOverall: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! QR authentication is working correctly.")
        else:
            print("⚠️ Some tests failed. Please check the issues above.")
        
        # Cleanup
        self.cleanup()
        
        return passed == total

def main():
    """Main test runner."""
    print("QR Code Authentication System Tester")
    print("This will test all aspects of QR code authentication")
    print("Make sure the server is running on http://localhost:5000")
    print()
    
    # Check if server is running
    try:
        response = requests.get(f"{TEST_SERVER_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
        else:
            print("❌ Server responded but not healthy")
            return False
    except requests.exceptions.RequestException:
        print("❌ Server is not running. Please start the server first.")
        return False
    
    # Run tests
    tester = QRAuthenticationTester()
    return tester.run_all_tests()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)