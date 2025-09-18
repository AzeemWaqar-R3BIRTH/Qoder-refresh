#!/usr/bin/env python3
"""
Robust email manager using direct SMTP instead of Flask-Mail
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import base64
import os
from datetime import datetime

class RobustEmailManager:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "azeemwaqar.work@gmail.com"
        self.sender_password = "wmwb ejkp sevx ipap"
        self.sender_name = "SecureTrainer"
    
    def send_welcome_email(self, user_email, user_name, qr_code_data):
        """Send welcome email with QR code attachment using direct SMTP."""
        try:
            print(f"📧 Sending welcome email to {user_email}...")
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.sender_name} <{self.sender_email}>"
            msg['To'] = user_email
            msg['Subject'] = "Welcome to SecureTrainer - Your QR Code is Ready!"
            
            # HTML Email body
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ 
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                        line-height: 1.6; 
                        color: #333; 
                        margin: 0; 
                        padding: 0; 
                        background-color: #f5f7fa;
                    }}
                    .email-container {{ 
                        max-width: 650px; 
                        margin: 0 auto; 
                        background: white; 
                        border-radius: 15px; 
                        overflow: hidden; 
                        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                    }}
                    .header {{ 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        color: white; 
                        padding: 40px 30px; 
                        text-align: center; 
                        position: relative;
                    }}
                    .header h1 {{ 
                        margin: 0; 
                        font-size: 32px; 
                        font-weight: 700; 
                        text-shadow: 0 2px 4px rgba(0,0,0,0.3);
                    }}
                    .header p {{ 
                        margin: 10px 0 0 0; 
                        font-size: 18px; 
                        opacity: 0.9; 
                        font-weight: 300;
                    }}
                    .content {{ 
                        padding: 40px 30px; 
                        background: white;
                    }}
                    .greeting {{ 
                        font-size: 24px; 
                        font-weight: 600; 
                        color: #2c3e50; 
                        margin-bottom: 20px;
                    }}
                    .intro-text {{ 
                        font-size: 16px; 
                        color: #555; 
                        margin-bottom: 25px; 
                        line-height: 1.7;
                    }}
                    .qr-section {{ 
                        background: linear-gradient(135deg, #f8f9ff 0%, #e8f2ff 100%); 
                        padding: 30px; 
                        margin: 30px 0; 
                        border-radius: 15px; 
                        text-align: center; 
                        border: 2px solid #667eea; 
                        box-shadow: 0 8px 25px rgba(102, 126, 234, 0.15);
                        position: relative;
                    }}
                    .qr-section::before {{
                        content: '🔐';
                        position: absolute;
                        top: -15px;
                        left: 50%;
                        transform: translateX(-50%);
                        background: white;
                        padding: 10px;
                        border-radius: 50%;
                        font-size: 24px;
                        border: 3px solid #667eea;
                    }}
                    .qr-title {{ 
                        font-size: 22px; 
                        font-weight: 700; 
                        color: #2c3e50; 
                        margin-bottom: 15px;
                    }}
                    .qr-description {{ 
                        font-size: 16px; 
                        color: #555; 
                        margin-bottom: 25px;
                    }}
                    .attachment-box {{ 
                        background: white; 
                        border: 2px dashed #667eea; 
                        padding: 25px; 
                        margin: 20px 0; 
                        border-radius: 12px; 
                        transition: all 0.3s ease;
                    }}
                    .attachment-icon {{ 
                        font-size: 48px; 
                        margin-bottom: 15px; 
                        color: #667eea;
                    }}
                    .attachment-filename {{ 
                        font-size: 18px; 
                        font-weight: 600; 
                        color: #2c3e50; 
                        margin-bottom: 10px;
                    }}
                    .attachment-description {{ 
                        font-size: 14px; 
                        color: #666; 
                        margin-bottom: 15px;
                    }}
                    .security-warning {{ 
                        background: #fff3cd; 
                        border: 2px solid #ffc107; 
                        padding: 15px; 
                        border-radius: 10px; 
                        margin: 15px 0;
                    }}
                    .security-warning .warning-icon {{ 
                        color: #ff9800; 
                        font-size: 20px; 
                        margin-right: 8px;
                    }}
                    .instructions-section {{ 
                        background: linear-gradient(135deg, #f0fff4 0%, #e8f5e8 100%); 
                        padding: 30px; 
                        margin: 30px 0; 
                        border-radius: 15px; 
                        border: 2px solid #28a745; 
                        box-shadow: 0 8px 25px rgba(40, 167, 69, 0.15);
                    }}
                    .instructions-title {{ 
                        font-size: 22px; 
                        font-weight: 700; 
                        color: #2c3e50; 
                        margin-bottom: 20px; 
                        text-align: center;
                    }}
                    .step {{ 
                        background: white; 
                        padding: 20px; 
                        margin: 15px 0; 
                        border-radius: 12px; 
                        border-left: 4px solid #28a745; 
                        box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                    }}
                    .step-number {{ 
                        background: #28a745; 
                        color: white; 
                        border-radius: 50%; 
                        width: 30px; 
                        height: 30px; 
                        display: inline-flex; 
                        align-items: center; 
                        justify-content: center; 
                        font-weight: bold; 
                        margin-right: 15px; 
                        font-size: 16px;
                    }}
                    .step-title {{ 
                        font-size: 18px; 
                        font-weight: 600; 
                        color: #2c3e50; 
                        margin-bottom: 8px;
                    }}
                    .step-description {{ 
                        font-size: 14px; 
                        color: #555; 
                        line-height: 1.6;
                    }}
                    .getting-started {{ 
                        background: #f8f9fa; 
                        padding: 25px; 
                        margin: 25px 0; 
                        border-radius: 12px; 
                        border-left: 4px solid #6c757d;
                    }}
                    .getting-started h3 {{ 
                        color: #2c3e50; 
                        margin-bottom: 15px; 
                        font-size: 20px;
                    }}
                    .getting-started ol {{ 
                        margin: 0; 
                        padding-left: 20px;
                    }}
                    .getting-started li {{ 
                        margin-bottom: 8px; 
                        color: #555; 
                        font-size: 15px;
                    }}
                    .learning-section {{ 
                        background: #fff5f5; 
                        padding: 25px; 
                        margin: 25px 0; 
                        border-radius: 12px; 
                        border-left: 4px solid #e74c3c;
                    }}
                    .learning-section h3 {{ 
                        color: #2c3e50; 
                        margin-bottom: 15px; 
                        font-size: 20px;
                    }}
                    .learning-section ul {{ 
                        margin: 0; 
                        padding-left: 20px;
                    }}
                    .learning-section li {{ 
                        margin-bottom: 8px; 
                        color: #555; 
                        font-size: 15px;
                    }}
                    .cta-button {{ 
                        display: inline-block; 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        color: white; 
                        padding: 15px 30px; 
                        text-decoration: none; 
                        border-radius: 25px; 
                        margin: 20px 0; 
                        font-weight: 600; 
                        font-size: 16px; 
                        text-align: center; 
                        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
                        transition: all 0.3s ease;
                    }}
                    .cta-button:hover {{ 
                        transform: translateY(-2px); 
                        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
                    }}
                    .footer {{ 
                        background: #2c3e50; 
                        color: #bdc3c7; 
                        padding: 25px; 
                        text-align: center; 
                        font-size: 13px; 
                        line-height: 1.5;
                    }}
                    .footer p {{ 
                        margin: 5px 0;
                    }}
                    .highlight {{ 
                        background: #e3f2fd; 
                        border: 2px solid #2196f3; 
                        padding: 20px; 
                        border-radius: 12px; 
                        margin: 20px 0;
                    }}
                    .highlight h4 {{ 
                        color: #1976d2; 
                        margin-bottom: 15px; 
                        text-align: center; 
                        font-size: 18px;
                    }}
                    @media (max-width: 600px) {{
                        .email-container {{ margin: 10px; }}
                        .header, .content {{ padding: 20px; }}
                        .header h1 {{ font-size: 24px; }}
                        .qr-section, .instructions-section {{ padding: 20px; }}
                    }}
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="header">
                        <div class="header-content">
                            <div class="logo">🛡️</div>
                            <h1>Welcome to SecureTrainer - Your QR Code is Ready!</h1>
                            <p>Welcome to SecureTrainer!<br>Your Cybersecurity Training Journey Begins Now</p>
                        </div>
                    </div>
                    
                    <div class="content">
                        <div class="greeting">Hello {user_name},</div>
                        
                        <div class="intro-text">
                            Welcome to <strong>SecureTrainer</strong>, the premier platform for enhancing cybersecurity awareness and skills in your organization!
                        </div>
                        
                        <div class="intro-text">
                            Your account has been successfully created and you're now ready to start your cybersecurity training journey.
                        </div>
                        
                        <div class="qr-section">
                            <div class="qr-title">Your Secure Login QR Code</div>
                            <div class="qr-description">This QR code is your secure login credential. Download and save it to your device.</div>
                            
                            <!-- Attachment Information -->
                            <div class="highlight">
                                <h4>📎 QR Code Attachment</h4>
                                <div class="attachment-box">
                                    <div class="attachment-icon">📱</div>
                                    <div class="attachment-filename">SecureTrainer_QR_Code_{qr_code_data['token'][:8]}.png</div>
                                    <div class="attachment-description">
                                        This QR code is your secure login credential. Download and save it to your device.
                                    </div>
                                    <div class="security-warning">
                                        <span class="warning-icon">⚠️</span>
                                        <strong>Important:</strong> Keep this QR code secure and don't share it with others.<br>
                                        This is your unique login credential that expires in 24 hours.
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Usage Instructions -->
                            <div class="instructions-section">
                                <div class="instructions-title">📱 How to use your QR code:</div>
                                
                                <div class="step">
                                    <span class="step-number">1</span>
                                    <div style="display: inline-block; vertical-align: top; width: calc(100% - 50px);">
                                        <div class="step-title">Download the QR Code</div>
                                        <div class="step-description">
                                            Look for the attached PNG file in this email and download it to your device. Save it in an easily accessible location.
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="step">
                                    <span class="step-number">2</span>
                                    <div style="display: inline-block; vertical-align: top; width: calc(100% - 50px);">
                                        <div class="step-title">Go to SecureTrainer Login</div>
                                        <div class="step-description">
                                            Visit the SecureTrainer platform and navigate to the login page.
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="step">
                                    <span class="step-number">3</span>
                                    <div style="display: inline-block; vertical-align: top; width: calc(100% - 50px);">
                                        <div class="step-title">Scan or Upload QR Code</div>
                                        <div class="step-description">
                                            Use the camera scanner on the login page to scan your QR code, or upload the downloaded PNG file if your camera isn't available.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="getting-started">
                            <h3>🚀 Getting Started</h3>
                            <ol>
                                <li><strong>Save this email</strong> - You'll need the QR code to log in</li>
                                <li><strong>Visit SecureTrainer</strong> - Go to the platform when you're ready to start</li>
                                <li><strong>Scan your QR code</strong> - Use the scanner on the login page</li>
                                <li><strong>Begin your training</strong> - Start with challenges tailored to your skill level</li>
                            </ol>
                        </div>
                        
                        <div class="learning-section">
                            <h3>🎯 What You'll Learn</h3>
                            <ul>
                                <li>SQL Injection prevention and detection</li>
                                <li>Cross-Site Scripting (XSS) vulnerabilities</li>
                                <li>Command injection attacks</li>
                                <li>Authentication and authorization best practices</li>
                                <li>And much more!</li>
                            </ul>
                        </div>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <p style="font-size: 16px; color: #555; margin-bottom: 20px;">
                                Your training progress will be tracked, and you'll earn points and promotions based on your performance!
                            </p>
                            <a href="http://127.0.0.1:5000/login" class="cta-button">Start Your Training Now</a>
                        </div>
                        
                    </div>
                    
                    <div class="footer">
                        <p><strong>SecureTrainer Team</strong></p>
                        <p>This is an automated message from SecureTrainer. Please do not reply to this email.</p>
                        <p>If you have any questions, contact your system administrator.</p>
                        <p style="margin-top: 15px; font-size: 11px; opacity: 0.7;">
                            © 2024 SecureTrainer. All rights reserved.
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Text version for email clients that don't support HTML
            text_body = f"""
            Welcome to SecureTrainer - Your QR Code is Ready!
            
            Welcome to SecureTrainer!
            Your Cybersecurity Training Journey Begins Now
            
            Hello {user_name},
            
            Welcome to SecureTrainer, the premier platform for enhancing cybersecurity awareness and skills in your organization!
            
            Your account has been successfully created and you're now ready to start your cybersecurity training journey.
            
            ========================================
            🔐 YOUR SECURE LOGIN QR CODE
            ========================================
            
            This QR code is your secure login credential. Download and save it to your device.
            Filename: SecureTrainer_QR_Code_{qr_code_data['token'][:8]}.png
            
            Important: Keep this QR code secure and don't share it with others.
            This is your unique login credential that expires in 24 hours.
            
            ========================================
            📱 HOW TO USE YOUR QR CODE
            ========================================
            
            1. Download the QR Code - Look for the attached PNG file in this email and download it to your device. Save it in an easily accessible location.
            
            2. Go to SecureTrainer Login - Visit the SecureTrainer platform and navigate to the login page.
            
            3. Scan or Upload QR Code - Use the camera scanner on the login page to scan your QR code, or upload the downloaded PNG file if your camera isn't available.
            
            ========================================
            🚀 GETTING STARTED
            ========================================
            
            1. Save this email - You'll need the QR code to log in
            2. Visit SecureTrainer - Go to the platform when you're ready to start
            3. Scan your QR code - Use the scanner on the login page
            4. Begin your training - Start with challenges tailored to your skill level
            
            ========================================
            🎯 WHAT YOU'LL LEARN
            ========================================
            
            - SQL Injection prevention and detection
            - Cross-Site Scripting (XSS) vulnerabilities
            - Command injection attacks
            - Authentication and authorization best practices
            - And much more!
            
            Your training progress will be tracked, and you'll earn points and promotions based on your performance!
            
            Start Your Training Now
            
            ========================================
            
            This is an automated message from SecureTrainer. Please do not reply to this email.
            
            If you have any questions, contact your system administrator.
            
            Best regards,
            The SecureTrainer Team
            """
            
            # Create multipart message with both HTML and text
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Attach QR code
            try:
                qr_image_data = base64.b64decode(qr_code_data['base64_data'])
                qr_attachment = MIMEImage(qr_image_data)
                qr_attachment.add_header('Content-Disposition', 'attachment', filename=f"SecureTrainer_QR_Code_{qr_code_data['token'][:8]}.png")
                msg.attach(qr_attachment)
                print(f"✅ QR code attached to email")
            except Exception as e:
                print(f"⚠️ Could not attach QR code: {e}")
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            print(f"✅ Welcome email sent successfully to {user_email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email to {user_email}: {e}")
            return False
    
    def send_test_email(self, recipient_email):
        """Send a test email to verify SMTP is working."""
        try:
            print(f"📧 Sending test email to {recipient_email}...")
            
            msg = MIMEMultipart()
            msg['From'] = f"{self.sender_name} <{self.sender_email}>"
            msg['To'] = recipient_email
            msg['Subject'] = "SecureTrainer Test Email"
            
            body = f"""
            This is a test email from SecureTrainer.
            
            If you received this email, the email system is working correctly!
            
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            Best regards,
            The SecureTrainer Team
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            print(f"✅ Test email sent successfully to {recipient_email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send test email to {recipient_email}: {e}")
            return False

if __name__ == "__main__":
    # Test the email manager
    manager = RobustEmailManager()
    manager.send_test_email("azeemwaqar95@gmail.com")