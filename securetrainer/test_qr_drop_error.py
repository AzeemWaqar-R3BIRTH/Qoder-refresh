#!/usr/bin/env python3
"""
Test QR code drag and drop errors
"""
import requests
import json
import time
import os
from app.utils.qr import QRCodeManager

def test_qr_drop_errors():
    """Test what errors occur when dropping QR images"""
    print("🔧 Testing QR Code Drag and Drop Errors...")
    
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
            print(f"📄 Upload response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Success: {data}")
            else:
                print(f"❌ Error response: {response.text}")
                
                # Try to parse as JSON
                try:
                    error_data = response.json()
                    print(f"❌ Error JSON: {error_data}")
                except:
                    print(f"❌ Error text (not JSON): {response.text}")
        else:
            print(f"❌ QR code file not found: {qr_data['filepath']}")
            
    except Exception as e:
        print(f"❌ File upload API failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test with different file names
    print("\n2. Testing with different field names...")
    try:
        if os.path.exists(qr_data['filepath']):
            with open(qr_data['filepath'], 'rb') as f:
                files = {'qr_file': f}  # Try the old field name
                response = requests.post('http://127.0.0.1:5000/api/auth/login', files=files, timeout=10)
            
            print(f"📡 qr_file response status: {response.status_code}")
            if response.status_code != 200:
                print(f"❌ qr_file error: {response.text}")
            
            # Try with both field names
            with open(qr_data['filepath'], 'rb') as f:
                files = {'qr_image': f, 'qr_file': f}
                response = requests.post('http://127.0.0.1:5000/api/auth/login', files=files, timeout=10)
            
            print(f"📡 Both fields response status: {response.status_code}")
            if response.status_code != 200:
                print(f"❌ Both fields error: {response.text}")
                
    except Exception as e:
        print(f"❌ Field name test failed: {e}")
    
    print("\n✅ QR Code Drag and Drop Error Test Completed!")

if __name__ == "__main__":
    print("🚀 Starting QR Code Drag and Drop Error Test...")
    test_qr_drop_errors()
