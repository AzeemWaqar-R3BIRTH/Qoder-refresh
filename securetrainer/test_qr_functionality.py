#!/usr/bin/env python3
"""
Test script for QR code functionality
"""
import requests
import json
import os
from app.utils.qr import QRCodeManager
from app.models.user_model import get_user_by_id

def test_qr_generation():
    """Test QR code generation"""
    print("🧪 Testing QR code generation...")
    
    qr_manager = QRCodeManager()
    
    # Generate a test QR code
    test_user_id = "507f1f77bcf86cd799439011"  # Example ObjectId
    test_email = "test@example.com"
    
    qr_data = qr_manager.generate_qr_code(test_user_id, test_email)
    
    print(f"✅ QR code generated:")
    print(f"   Token: {qr_data['token']}")
    print(f"   File: {qr_data['filepath']}")
    print(f"   Expires: {qr_data['expires']}")
    
    return qr_data

def test_qr_validation(qr_data):
    """Test QR code validation"""
    print("\n🧪 Testing QR code validation...")
    
    qr_manager = QRCodeManager()
    
    # Test validation with JSON string
    qr_data_str = json.dumps(qr_data['qr_data'])
    is_valid, result = qr_manager.validate_qr_code(qr_data_str)
    
    print(f"✅ QR validation result:")
    print(f"   Valid: {is_valid}")
    print(f"   Result: {result}")
    
    return is_valid, result

def test_api_endpoints():
    """Test API endpoints"""
    print("\n🧪 Testing API endpoints...")
    
    base_url = "http://127.0.0.1:5000"
    
    # Test demo login
    try:
        response = requests.get(f"{base_url}/demo-login", timeout=5)
        print(f"✅ Demo login endpoint: {response.status_code}")
        if response.status_code == 302:
            print("   Redirected to dashboard")
    except Exception as e:
        print(f"❌ Demo login failed: {e}")
    
    # Test login page
    try:
        response = requests.get(f"{base_url}/login", timeout=5)
        print(f"✅ Login page: {response.status_code}")
    except Exception as e:
        print(f"❌ Login page failed: {e}")

def test_qr_upload():
    """Test QR code file upload"""
    print("\n🧪 Testing QR code file upload...")
    
    # Generate a test QR code
    qr_manager = QRCodeManager()
    test_user_id = "507f1f77bcf86cd799439011"
    test_email = "test@example.com"
    
    qr_data = qr_manager.generate_qr_code(test_user_id, test_email)
    qr_file_path = qr_data['filepath']
    
    if os.path.exists(qr_file_path):
        print(f"✅ QR code file exists: {qr_file_path}")
        
        # Test file upload to API
        try:
            with open(qr_file_path, 'rb') as f:
                files = {'qr_image': f}
                response = requests.post('http://127.0.0.1:5000/api/auth/login', files=files, timeout=10)
                
            print(f"✅ QR upload API response: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"   Response: {data}")
            else:
                print(f"   Error: {response.text}")
        except Exception as e:
            print(f"❌ QR upload failed: {e}")
    else:
        print(f"❌ QR code file not found: {qr_file_path}")

def test_qr_camera_data():
    """Test QR code camera data"""
    print("\n🧪 Testing QR code camera data...")
    
    # Generate a test QR code
    qr_manager = QRCodeManager()
    test_user_id = "507f1f77bcf86cd799439011"
    test_email = "test@example.com"
    
    qr_data = qr_manager.generate_qr_code(test_user_id, test_email)
    qr_data_str = json.dumps(qr_data['qr_data'])
    
    # Test camera data API
    try:
        payload = {'qr_data': qr_data_str}
        response = requests.post('http://127.0.0.1:5000/api/auth/login', 
                               json=payload, 
                               headers={'Content-Type': 'application/json'},
                               timeout=10)
        
        print(f"✅ QR camera data API response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {data}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"❌ QR camera data failed: {e}")

if __name__ == "__main__":
    print("🚀 Starting QR Code Functionality Tests...")
    
    # Test QR generation
    qr_data = test_qr_generation()
    
    # Test QR validation
    test_qr_validation(qr_data)
    
    # Test API endpoints
    test_api_endpoints()
    
    # Test QR upload
    test_qr_upload()
    
    # Test QR camera data
    test_qr_camera_data()
    
    print("\n✅ QR Code functionality tests completed!")
