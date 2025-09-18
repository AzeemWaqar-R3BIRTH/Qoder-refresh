#!/usr/bin/env python3
"""
Test script to verify email functionality
"""

import os
import sys
from flask import Flask
from flask_mail import Mail

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Create Flask app
app = Flask(__name__)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='azeemwaqar.work@gmail.com',
    MAIL_PASSWORD='wmwb ejkp sevx ipap'
)

# Initialize Mail
mail = Mail(app)

# Import EmailManager
from app.utils.email import EmailManager
from app.utils.qr import QRCodeManager

def test_email():
    """Test email sending functionality."""
    try:
        # Initialize managers
        email_manager = EmailManager(mail)
        qr_manager = QRCodeManager()
        
        print("✅ Managers initialized successfully")
        
        # Generate test QR code
        test_user_id = "test_user_123"
        test_email = "test@example.com"
        qr_data = qr_manager.generate_qr_code(test_user_id, test_email)
        
        print("✅ QR code generated successfully")
        print(f"QR Data: {qr_data}")
        
        # Test email sending
        with app.app_context():
            email_manager.send_welcome_email(
                test_email,
                "Test User",
                qr_data
            )
            print("✅ Email sent successfully!")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_email()
