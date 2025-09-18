#!/usr/bin/env python3
"""
Simple QR code test
"""
import requests
import json
import time
import os
from app.utils.qr import QRCodeManager

def test_simple_qr():
    """Test simple QR code functionality"""
    print("🔧 Testing Simple QR Code Functionality...")
    
    # Generate test QR code
    qr_manager = QRCodeManager()
    test_user_id = "507f1f77bcf86cd799439011"
    test_email = "test@example.com"
    
    qr_data = qr_manager.generate_qr_code(test_user_id, test_email)
    print(f"✅ QR code generated: {qr_data['filepath']}")
    
    # Test file upload API
    print("\n1. Testing File Upload API...")
    try:
        if os.path.exists(qr_data['filepath']):
            with open(qr_data['filepath'], 'rb') as f:
                files = {'qr_image': f}
                response = requests.post('http://127.0.0.1:5000/api/auth/login', files=files, timeout=10)
            
            print(f"📡 Upload response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Success: {data}")
            else:
                print(f"❌ Error response: {response.text}")
        else:
            print(f"❌ QR code file not found: {qr_data['filepath']}")
            
    except Exception as e:
        print(f"❌ File upload API failed: {e}")
    
    print("\n✅ Simple QR Code Test Completed!")

if __name__ == "__main__":
    print("🚀 Starting Simple QR Code Test...")
    test_simple_qr()
