#!/usr/bin/env python3
"""
Simple script to create the .env file with the correct configuration.
"""

env_content = '''# SecureTrainer Environment Configuration
# Final Year Project - Cybersecurity Training Platform

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Flask Secret Key
SECRET_KEY="Azeem and Saffan Developed this AI Driven Cyber Security Training Application in Supervision of Dr Shahbaz Siddiqui and Dr Fahad Samad"

# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================

# Email Server Settings
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USE_SSL=False

# Email Credentials
MAIL_USERNAME="azeemwaqar.work@gmail.com"
MAIL_PASSWORD="wmwb ejkp sevx ipap"

# Email Display Settings
MAIL_DEFAULT_SENDER=SecureTrainer <azeemwaqar.work@gmail.com>
MAIL_MAX_EMAILS=10

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# MongoDB Connection String
MONGO_URI=mongodb://localhost:27017/securetrainer

# Database Name
MONGO_DB_NAME=securetrainer

# =============================================================================
# APPLICATION SETTINGS
# =============================================================================

# Flask Environment
FLASK_ENV=development
FLASK_DEBUG=True

# Server Configuration
HOST=0.0.0.0
PORT=5000

# Application URL (for email links)
APP_URL=http://localhost:5000

# =============================================================================
# AI/ML MODEL CONFIGURATION
# =============================================================================

# Model Paths
MODEL_PATH=./model/challenge_difficulty_model.pkl
LABEL_ENCODER_PATH=./model/label_encoder.pkl

# AI Model Settings
AI_ENABLED=True
AI_FALLBACK_ENABLED=True

# =============================================================================
# QR CODE CONFIGURATION
# =============================================================================

# QR Code Storage
QR_STORAGE_PATH=./qr_codes
QR_EXPIRY_HOURS=24

# QR Code Security
QR_TOKEN_LENGTH=32
QR_ENCRYPTION_KEY=secure-qr-encryption-key-2025

# =============================================================================
# CHALLENGE SYSTEM CONFIGURATION
# =============================================================================

# Challenge Settings
MAX_HINTS_PER_CHALLENGE=3
HINT_PENALTY_PERCENTAGE=10
BASE_CHALLENGE_POINTS=100
LEVEL_UP_THRESHOLD=1000

# Challenge Categories
ENABLED_CHALLENGES=sql_injection,xss,command_injection,authentication,csrf

# =============================================================================
# GAMIFICATION SETTINGS
# =============================================================================

# Scoring System
POINTS_PER_CHALLENGE=100
BONUS_POINTS_PER_LEVEL=50
HINT_PENALTY=10
TIME_BONUS_THRESHOLD=300

# Role Progression
ROLES=Trainee,Analyst,Senior Analyst,Department Head,Chief Security Officer
ROLE_UPGRADE_THRESHOLDS=0,1000,2500,5000,10000

# =============================================================================
# ADMINISTRATION
# =============================================================================

# Admin Token
ADMIN_TOKEN=supersecretadmintoken123

# =============================================================================
# LOGGING AND MONITORING
# =============================================================================

# Log Level
LOG_LEVEL=INFO

# Log File Path
LOG_FILE_PATH=./logs/securetrainer.log

# =============================================================================
# SECURITY FEATURES
# =============================================================================

# Session Timeout (in seconds)
SESSION_TIMEOUT=3600

# Password Policy
MIN_PASSWORD_LENGTH=8
REQUIRE_SPECIAL_CHARS=True
REQUIRE_NUMBERS=True
REQUIRE_UPPERCASE=True

# Rate Limiting
MAX_LOGIN_ATTEMPTS=5
LOGIN_TIMEOUT=900
'''

if __name__ == "__main__":
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ .env file created successfully!")
        print("📧 Email configuration: azeemwaqar.work@gmail.com")
        print("🗄️ MongoDB URI: mongodb://localhost:27017/securetrainer")
        print("🔑 Secret key configured")
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
