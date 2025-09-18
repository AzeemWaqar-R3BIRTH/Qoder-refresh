#!/usr/bin/env python3
"""
Debug script to test registration functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from securetrainer import app, db, qr_manager, email_manager
import json

def test_registration():
    """Test registration with sample data"""
    print("🔍 Testing registration functionality...")
    
    # Test data
    test_data = {
        'first_name': 'Test',
        'last_name': 'User',
        'username': 'testuser456',
        'email': 'test456@example.com',
        'password': 'testpass123',
        'company': 'TestCorp',
        'department': 'IT'
    }
    
    print(f"📝 Test data: {test_data}")
    
    # Test database connection
    print(f"🗄️ Database connection: {'✅ Connected' if db is not None else '❌ Failed'}")
    
    # Test QR manager
    try:
        print("🔍 Testing QR manager...")
        qr_data = qr_manager.generate_qr_code("test_user_id", "test@example.com")
        print(f"✅ QR manager working: {type(qr_data)}")
    except Exception as e:
        print(f"❌ QR manager error: {e}")
        return False
    
    # Test email manager
    try:
        print("📧 Testing email manager...")
        result = email_manager.send_welcome_email("test@example.com", "Test User", qr_data)
        print(f"✅ Email manager working: {result}")
    except Exception as e:
        print(f"❌ Email manager error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test user creation
    try:
        print("👤 Testing user creation...")
        if db is not None:
            # Check if user already exists
            existing_user = db.users.find_one({'$or': [{'username': test_data['username']}, {'email': test_data['email']}]})
            if existing_user:
                print(f"⚠️ User already exists: {existing_user['username']}")
                return True
            
            # Create user
            import bcrypt
            hashed_password = bcrypt.hashpw(test_data['password'].encode('utf-8'), bcrypt.gensalt())
            
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
            
            result = db.users.insert_one(user_data)
            user_id = result.inserted_id
            print(f"✅ User created with ID: {user_id}")
            
            # Generate QR code
            qr_data = qr_manager.generate_qr_code(str(user_id), test_data['email'])
            print(f"✅ QR code generated: {type(qr_data)}")
            
            # Send email
            email_result = email_manager.send_welcome_email(test_data['email'], f"{test_data['first_name']} {test_data['last_name']}", qr_data)
            print(f"✅ Email sent: {email_result}")
            
            return True
        else:
            print("❌ Database not available")
            return False
            
    except Exception as e:
        print(f"❌ User creation error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    from datetime import datetime
    success = test_registration()
    print(f"\n{'✅ Registration test passed!' if success else '❌ Registration test failed!'}")
