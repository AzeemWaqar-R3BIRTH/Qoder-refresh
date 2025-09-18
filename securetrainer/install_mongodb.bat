@echo off
echo ========================================
echo    MongoDB Installation Helper Script
echo    SecureTrainer Project Setup
echo ========================================
echo.

echo Checking if MongoDB is already installed...
mongod --version >nul 2>&1
if %errorlevel% == 0 (
    echo ✅ MongoDB is already installed!
    goto :check_service
) else (
    echo ❌ MongoDB not found. Please install MongoDB first.
    echo.
    echo 📥 Download MongoDB from: https://mongodb.com/try/download/community
    echo 📖 Installation Guide: https://docs.mongodb.com/manual/installation/
    echo.
    pause
    exit /b 1
)

:check_service
echo.
echo Checking MongoDB service status...
sc query MongoDB >nul 2>&1
if %errorlevel% == 0 (
    echo ✅ MongoDB service found
    sc query MongoDB | find "RUNNING" >nul 2>&1
    if %errorlevel% == 0 (
        echo ✅ MongoDB service is running
    ) else (
        echo ⚠️ MongoDB service is not running. Starting it...
        net start MongoDB
        if %errorlevel% == 0 (
            echo ✅ MongoDB service started successfully
        ) else (
            echo ❌ Failed to start MongoDB service
            echo 💡 Try running as Administrator
        )
    )
) else (
    echo ⚠️ MongoDB service not found. Starting MongoDB manually...
    echo 💡 This will start MongoDB in the foreground
    echo 💡 Press Ctrl+C to stop when done
    echo.
    pause
    mongod --dbpath C:\data\db
)

:create_directories
echo.
echo Creating required directories...
if not exist "logs" mkdir logs
if not exist "qr_codes" mkdir qr_codes
if not exist "backups" mkdir backups
if not exist "C:\data\db" mkdir "C:\data\db"
echo ✅ Directories created

:test_connection
echo.
echo Testing MongoDB connection...
echo "db.runCommand('ping')" | mongosh --quiet >nul 2>&1
if %errorlevel% == 0 (
    echo ✅ MongoDB connection successful!
    echo.
    echo 🎉 MongoDB is ready for SecureTrainer!
    echo.
    echo 📝 Next steps:
    echo 1. Run: python create_env.py
    echo 2. Run: python start.py
    echo 3. Open: http://localhost:5000
) else (
    echo ❌ MongoDB connection failed
    echo 💡 Make sure MongoDB is running
    echo 💡 Check if port 27017 is available
)

echo.
pause
