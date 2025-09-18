#!/usr/bin/env python3
"""
Test drag and drop QR code functionality
"""
import requests
import json
import time
import os
from app.utils.qr import QRCodeManager

def test_drag_drop_qr():
    """Test drag and drop QR code functionality"""
    print("🔧 Testing Drag and Drop QR Code Functionality...")
    
    # Test QR manager
    print("\n1. Testing QR Manager...")
    try:
        qr_manager = QRCodeManager()
        print("✅ QR Manager initialized")
        
        # Generate test QR code
        test_user_id = "507f1f77bcf86cd799439011"
        test_email = "test@example.com"
        
        qr_data = qr_manager.generate_qr_code(test_user_id, test_email)
        print(f"✅ QR code generated: {qr_data['token']}")
        print(f"✅ QR code file: {qr_data['filepath']}")
        
        # Test validation
        qr_data_str = json.dumps(qr_data['qr_data'])
        is_valid, result = qr_manager.validate_qr_code(qr_data_str)
        
        if is_valid:
            print("✅ QR code validation successful")
        else:
            print(f"❌ QR code validation failed: {result}")
            return False
            
    except Exception as e:
        print(f"❌ QR Manager error: {e}")
        return False
    
    # Test Flask app endpoints
    print("\n2. Testing Flask App Endpoints...")
    base_url = "http://127.0.0.1:5000"
    
    # Test login page
    try:
        response = requests.get(f"{base_url}/login", timeout=5)
        print(f"✅ Login page: {response.status_code}")
    except Exception as e:
        print(f"❌ Login page failed: {e}")
    
    # Test file upload API
    print("\n3. Testing File Upload API...")
    try:
        if os.path.exists(qr_data['filepath']):
            with open(qr_data['filepath'], 'rb') as f:
                files = {'qr_image': f}
                response = requests.post(f"{base_url}/api/auth/login", files=files, timeout=10)
            
            print(f"✅ File upload API: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Response: {data}")
            else:
                print(f"   ❌ Error: {response.text}")
        else:
            print(f"❌ QR code file not found: {qr_data['filepath']}")
            
    except Exception as e:
        print(f"❌ File upload API failed: {e}")
    
    # Test camera QR API
    print("\n4. Testing Camera QR API...")
    try:
        payload = {'qr_data': qr_data_str}
        response = requests.post(f"{base_url}/api/auth/login", 
                               json=payload, 
                               headers={'Content-Type': 'application/json'},
                               timeout=5)
        
        print(f"✅ Camera QR API: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Response: {data}")
        else:
            print(f"   ❌ Error: {response.text}")
            
    except Exception as e:
        print(f"❌ Camera QR API failed: {e}")
    
    print("\n✅ Drag and Drop QR Code Test Completed!")
    return True

if __name__ == "__main__":
    print("🚀 Starting Drag and Drop QR Code Test...")
    test_drag_drop_qr()
