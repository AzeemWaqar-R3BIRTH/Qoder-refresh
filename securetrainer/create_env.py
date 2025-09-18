#!/usr/bin/env python3
"""
Create .env file with user's specific configuration
"""

def create_env_file():
    """Create the .env file with the user's configuration."""
    
    env_content = """# SecureTrainer Environment Configuration
# Final Year Project - Cybersecurity Training Platform
# Developed by Azeem and Saffan under supervision of Dr Shahbaz Siddiqui and Dr Fahad Samad

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Flask Secret Key
SECRET_KEY=Azeem and Saffan Developed this AI Driven Cyber Security Training Application in Supervision of Dr Shahbaz Siddiqui and Dr Fahad Samad

# Admin Token
ADMIN_TOKEN=supersecretadmintoken123

# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================

# Email Server Settings
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USE_SSL=False

# Email Credentials
MAIL_USERNAME=azeemwaqar.work@gmail.com
MAIL_PASSWORD=wmwb ejkp sevx ipap

# Email Display Settings
MAIL_DEFAULT_SENDER=SecureTrainer <azeemwaqar.work@gmail.com>
MAIL_MAX_EMAILS=10

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# MongoDB Connection String
MONGO_URI=mongodb://localhost:27017/securetrainer
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
QR_ENCRYPTION_KEY=securetrainer_qr_encryption_key_2024

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
POINTS_MULTIPLIER=1.0
BONUS_POINTS_ENABLED=True
STREAK_BONUS_ENABLED=True

# Role Progression
ROLE_THRESHOLDS=1000,2500,5000,10000,20000
ROLE_NAMES=Trainee,Analyst,Specialist,Expert,Department Head

# =============================================================================
# LOGGING AND MONITORING
# =============================================================================

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=./logs/securetrainer.log
LOG_MAX_SIZE=10MB
LOG_BACKUP_COUNT=5

# Performance Monitoring
ENABLE_METRICS=True
METRICS_INTERVAL=60

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# Session Configuration
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600

# Rate Limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600

# CSRF Protection
CSRF_ENABLED=True
CSRF_TIME_LIMIT=3600

# =============================================================================
# DEVELOPMENT SETTINGS
# =============================================================================

# Debug Mode
DEBUG=True
TESTING=False

# Auto-reload
AUTO_RELOAD=True

# Development Tools
ENABLE_PROFILER=False
ENABLE_DEBUG_TOOLBAR=False

# =============================================================================
# NOTIFICATION SETTINGS
# =============================================================================

# Email Notifications
SEND_WELCOME_EMAIL=True
SEND_CHALLENGE_COMPLETION_EMAIL=True
SEND_PROMOTION_EMAIL=True
SEND_WEEKLY_PROGRESS_EMAIL=False

# =============================================================================
# CUSTOMIZATION SETTINGS
# =============================================================================

# Company Branding
COMPANY_NAME=SecureTrainer
COMPANY_WEBSITE=https://securetrainer.com
THEME_COLOR=#1e40af
ACCENT_COLOR=#f59e0b
SUCCESS_COLOR=#10b981
ERROR_COLOR=#ef4444

# =============================================================================
# PROJECT INFORMATION
# =============================================================================

# Project Details
PROJECT_NAME=SecureTrainer
PROJECT_VERSION=1.0.0
PROJECT_DESCRIPTION=AI-Driven Cybersecurity Training Platform
DEVELOPERS=Azeem and Saffan
SUPERVISORS=Dr Shahbaz Siddiqui and Dr Fahad Samad
INSTITUTION=Final Year Project - Bachelor's in Cyber Security
YEAR=2024

# =============================================================================
# NOTES
# =============================================================================

# This configuration file is specifically set up for:
# - Gmail SMTP server with App Password authentication
# - Local MongoDB database
# - Development environment
# - AI-powered cybersecurity training platform
# 
# Remember to:
# 1. Never commit this file to version control
# 2. Keep your credentials secure
# 3. Update settings for production deployment
# 4. Monitor logs for any issues
"""
    
    # Write the .env file
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        
        print("✅ .env file created successfully!")
        print("📧 Email configured with: azeemwaqar.work@gmail.com")
        print("🗄️ Database: mongodb://localhost:27017/securetrainer")
        print("🔐 Secret key and admin token configured")
        print("\n📝 Next steps:")
        print("1. Ensure MongoDB is running locally")
        print("2. Create required directories: mkdir logs qr_codes backups")
        print("3. Run 'python start.py' to start the application")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False

if __name__ == '__main__':
    print("🛡️ Creating SecureTrainer .env file...")
    create_env_file()
