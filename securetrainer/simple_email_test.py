#!/usr/bin/env python3
"""
Simple email test to verify Gmail SMTP is working
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import base64
import qrcode
from io import BytesIO

def test_simple_email():
    """Test sending a simple email with QR code"""
    
    # Email configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "azeemwaqar.work@gmail.com"
    sender_password = "wmwb ejkp sevx ipap"
    recipient_email = "k213562@nu.edu.pk"  # Your email from the registration
    
    try:
        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data("test_qr_data_for_securetrainer")
        qr.make(fit=True)
        
        # Create QR code image
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = BytesIO()
        qr_img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        qr_image_data = img_buffer.getvalue()
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = "SecureTrainer - Test QR Code"
        
        # Email body
        body = """
        Hello!
        
        This is a test email from SecureTrainer to verify email delivery.
        
        Your QR code is attached to this email.
        
        Best regards,
        SecureTrainer Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach QR code
        qr_attachment = MIMEImage(qr_image_data)
        qr_attachment.add_header('Content-Disposition', 'attachment', filename='test_qr_code.png')
        msg.attach(qr_attachment)
        
        # Send email
        print(f"📧 Sending test email to {recipient_email}...")
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        print("✅ Test email sent successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        return False

if __name__ == "__main__":
    test_simple_email()
