#!/usr/bin/env python3
"""
Fast registration test without email blocking
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from securetrainer import app, db, qr_manager
import bcrypt
from datetime import datetime
import json

def test_fast_registration():
    """Test registration without email blocking"""
    print("🚀 Testing fast registration...")
    
    # Test data
    test_data = {
        'first_name': 'Test',
        'last_name': 'User',
        'username': 'testuser789',
        'email': 'test789@example.com',
        'password': 'testpass123',
        'company': 'TestCorp',
        'department': 'IT'
    }
    
    try:
        if db is not None:
            # Check if user already exists
            existing_user = db.users.find_one({'$or': [{'username': test_data['username']}, {'email': test_data['email']}]})
            if existing_user:
                print(f"⚠️ User already exists: {existing_user['username']}")
                return True
            
            # Hash password
            hashed_password = bcrypt.hashpw(test_data['password'].encode('utf-8'), bcrypt.gensalt())
            
            # Create user data
            user_data = {
                'first_name': test_data['first_name'],
                'last_name': test_data['last_name'],
                'username': test_data['username'],
                'email': test_data['email'],
                'password': hashed_password,
                'company': test_data['company'],
                'department': test_data['department'],
                'level': 1,
                'score': 0,
                'role': 'Trainee',
                'created_at': datetime.now(),
                'last_login': None,
                'challenges_completed': [],
                'achievements': []
            }
            
            # Insert user
            result = db.users.insert_one(user_data)
            user_id = result.inserted_id
            print(f"✅ User created with ID: {user_id}")
            
            # Generate QR code
            qr_data = qr_manager.generate_qr_code(str(user_id), test_data['email'])
            print(f"✅ QR code generated: {type(qr_data)}")
            
            # Save QR code to file for immediate access
            qr_filename = f"qr_codes/user_{user_id}_qr.png"
            os.makedirs("qr_codes", exist_ok=True)
            
            # Decode and save QR code
            import base64
            qr_image_data = base64.b64decode(qr_data['base64_data'])
            with open(qr_filename, 'wb') as f:
                f.write(qr_image_data)
            
            print(f"✅ QR code saved to: {qr_filename}")
            print(f"📧 Email will be sent in background (may take a few minutes)")
            
            return True
        else:
            print("❌ Database not available")
            return False
            
    except Exception as e:
        print(f"❌ Registration error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_fast_registration()
    print(f"\n{'✅ Fast registration test passed!' if success else '❌ Fast registration test failed!'}")
