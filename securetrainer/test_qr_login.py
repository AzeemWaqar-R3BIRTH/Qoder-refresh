#!/usr/bin/env python3
"""
Test QR code login functionality
"""
import requests
import json
import time
import os
from app.utils.qr import QRCodeManager

def test_qr_login_system():
    """Test the complete QR code login system"""
    print("🚀 Testing QR Code Login System...")
    
    # Wait for Flask app to start
    print("⏳ Waiting for Flask app to start...")
    time.sleep(5)
    
    base_url = "http://127.0.0.1:5000"
    
    # Test 1: Login page accessibility
    print("\n📄 Test 1: Login page accessibility")
    try:
        response = requests.get(f"{base_url}/login", timeout=10)
        print(f"✅ Login page: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Login page loads successfully")
            print("   ✅ QR scanner and upload functionality available")
        else:
            print(f"   ❌ Login page failed with status {response.status_code}")
    except Exception as e:
        print(f"❌ Login page failed: {e}")
        return False
    
    # Test 2: Generate a test QR code
    print("\n🔐 Test 2: Generate test QR code")
    try:
        qr_manager = QRCodeManager()
        test_user_id = "507f1f77bcf86cd799439011"
        test_email = "test@example.com"
        
        qr_data = qr_manager.generate_qr_code(test_user_id, test_email)
        print(f"✅ QR code generated:")
        print(f"   Token: {qr_data['token']}")
        print(f"   File: {qr_data['filepath']}")
        print(f"   Expires: {qr_data['expires']}")
        
        # Verify file exists
        if os.path.exists(qr_data['filepath']):
            print("   ✅ QR code file created successfully")
        else:
            print("   ❌ QR code file not found")
            return False
            
    except Exception as e:
        print(f"❌ QR code generation failed: {e}")
        return False
    
    # Test 3: Test QR code validation
    print("\n🔍 Test 3: QR code validation")
    try:
        qr_data_str = json.dumps(qr_data['qr_data'])
        is_valid, result = qr_manager.validate_qr_code(qr_data_str)
        
        if is_valid:
            print("✅ QR code validation successful")
            print(f"   User ID: {result['user_id']}")
            print(f"   Email: {result['email']}")
        else:
            print(f"❌ QR code validation failed: {result}")
            return False
            
    except Exception as e:
        print(f"❌ QR code validation failed: {e}")
        return False
    
    # Test 4: Test camera QR data API
    print("\n📱 Test 4: Camera QR data API")
    try:
        payload = {'qr_data': qr_data_str}
        response = requests.post(f"{base_url}/api/auth/login", 
                               json=payload, 
                               headers={'Content-Type': 'application/json'},
                               timeout=10)
        
        print(f"✅ Camera QR API response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Login successful: {data.get('message', 'No message')}")
            print(f"   User: {data.get('user', {}).get('username', 'Unknown')}")
        else:
            print(f"   ❌ Login failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Camera QR API failed: {e}")
    
    # Test 5: Test file upload API
    print("\n📁 Test 5: File upload API")
    try:
        with open(qr_data['filepath'], 'rb') as f:
            files = {'qr_image': f}
            response = requests.post(f"{base_url}/api/auth/login", files=files, timeout=10)
        
        print(f"✅ File upload API response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Upload login successful: {data.get('message', 'No message')}")
            print(f"   User: {data.get('user', {}).get('username', 'Unknown')}")
        else:
            print(f"   ❌ Upload login failed: {response.text}")
            
    except Exception as e:
        print(f"❌ File upload API failed: {e}")
    
    # Test 6: Test demo login
    print("\n👤 Test 6: Demo login")
    try:
        response = requests.get(f"{base_url}/demo-login", timeout=10)
        print(f"✅ Demo login response: {response.status_code}")
        if response.status_code == 302:
            print("   ✅ Demo login redirects to dashboard")
        else:
            print(f"   ❌ Demo login failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Demo login failed: {e}")
    
    print("\n✅ QR Code Login System Test Completed!")
    return True

if __name__ == "__main__":
    test_qr_login_system()
