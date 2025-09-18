# 🗄️ MongoDB Installation Guide for SecureTrainer

## 🚀 **Quick Start (Recommended)**

### **Option 1: Automated Setup**
```bash
# Run the helper script (as Administrator)
install_mongodb.bat
```

### **Option 2: Manual Installation**
Follow the detailed steps below.

## 📥 **Download MongoDB**

### **Step 1: Visit Official Site**
- **URL**: [mongodb.com/try/download/community](https://mongodb.com/try/download/community)
- **Version**: 7.0.5 (Latest Stable)
- **Platform**: Windows
- **Package**: MSI Installer

### **Step 2: Download Options**
- **MongoDB Community Server**: Core database
- **MongoDB Compass**: GUI management tool (recommended)
- **MongoDB Shell**: Command-line interface

## 🔧 **Installation Process**

### **Step 1: Run Installer**
1. **Right-click** the downloaded `.msi` file
2. **Run as Administrator**
3. **Accept** the license agreement

### **Step 2: Installation Type**
- **Complete**: Full installation (recommended)
- **Custom**: Select specific components
- **Install MongoDB Compass**: ✅ Check this
- **Install as a Service**: ✅ Check this

### **Step 3: Configuration**
- **Data Directory**: `C:\Program Files\MongoDB\Server\7.0\data`
- **Log Directory**: `C:\Program Files\MongoDB\Server\7.0\log`
- **Service Name**: `MongoDB`

### **Step 4: Complete Installation**
- **Install**: Click to begin
- **Wait**: Installation takes 2-5 minutes
- **Finish**: Restart if prompted

## ✅ **Post-Installation Setup**

### **Step 1: Create Data Directory**
```bash
# Open Command Prompt as Administrator
mkdir C:\data\db
```

### **Step 2: Start MongoDB Service**
```bash
# Method 1: Start Windows Service
net start MongoDB

# Method 2: Start manually
mongod --dbpath C:\data\db
```

### **Step 3: Verify Installation**
```bash
# Check MongoDB version
mongod --version

# Check if service is running
sc query MongoDB

# Connect to MongoDB
mongosh
```

## 🔍 **Troubleshooting**

### **Common Issues**

#### **1. "MongoDB service failed to start"**
```bash
# Check Windows Event Viewer
eventvwr.msc

# Check MongoDB logs
type "C:\Program Files\MongoDB\Server\7.0\log\mongod.log"
```

#### **2. "Port 27017 is already in use"**
```bash
# Check what's using the port
netstat -ano | findstr :27017

# Kill the process
taskkill /PID <PID> /F
```

#### **3. "Access denied" errors**
- **Run Command Prompt as Administrator**
- **Check Windows Firewall settings**
- **Verify service permissions**

### **Service Management**
```bash
# Start MongoDB service
net start MongoDB

# Stop MongoDB service
net stop MongoDB

# Restart MongoDB service
net stop MongoDB && net start MongoDB

# Check service status
sc query MongoDB
```

## 🌐 **Alternative: MongoDB Atlas (Cloud)**

### **Benefits**
- ✅ No installation required
- ✅ Free tier available
- ✅ Managed service
- ✅ Automatic backups

### **Setup Steps**
1. **Create Account**: [mongodb.com/atlas](https://mongodb.com/atlas)
2. **Create Cluster**: Free tier (M0)
3. **Get Connection String**:
   ```
   mongodb+srv://username:password@cluster.mongodb.net/securetrainer?retryWrites=true&w=majority
   ```
4. **Update `.env` file**:
   ```env
   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/securetrainer?retryWrites=true&w=majority
   ```

## 📁 **Directory Structure**

After installation, create these directories in your project:
```bash
securetrainer/
├── logs/           # Application logs
├── qr_codes/       # Generated QR codes
├── backups/        # Database backups
└── .env            # Environment configuration
```

## 🧪 **Testing Your Installation**

### **Test 1: Basic Connection**
```bash
# Connect to MongoDB
mongosh

# Test database operations
use securetrainer
db.createCollection("test")
db.test.insertOne({name: "SecureTrainer", version: "1.0.0"})
db.test.find()
exit
```

### **Test 2: Python Connection**
```python
# Test Python MongoDB connection
from pymongo import MongoClient

try:
    client = MongoClient("mongodb://localhost:27017/")
    db = client.securetrainer
    print("✅ MongoDB connection successful!")
    client.close()
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
```

## 🔒 **Security Considerations**

### **Development Environment**
- **Bind IP**: `127.0.0.1` (localhost only)
- **Authentication**: Disabled (for development)
- **Firewall**: Allow port 27017

### **Production Environment**
- **Enable Authentication**: Create admin users
- **Network Security**: Restrict access
- **SSL/TLS**: Enable encryption
- **Regular Updates**: Keep MongoDB updated

## 📊 **Performance Optimization**

### **Memory Settings**
```bash
# MongoDB configuration file
# C:\Program Files\MongoDB\Server\7.0\bin\mongod.cfg

storage:
  dbPath: C:\data\db
  journal:
    enabled: true

systemLog:
  destination: file
  logAppend: true
  path: C:\Program Files\MongoDB\Server\7.0\log\mongod.log

net:
  port: 27017
  bindIp: 127.0.0.1
```

## 🎯 **Next Steps for SecureTrainer**

1. **Install MongoDB**: Follow this guide
2. **Create `.env` file**: `python create_env.py`
3. **Start application**: `python start.py`
4. **Access platform**: `http://localhost:5000`

## 📞 **Need Help?**

### **Official Resources**
- **Documentation**: [docs.mongodb.com](https://docs.mongodb.com)
- **Community**: [community.mongodb.com](https://community.mongodb.com)
- **Support**: [mongodb.com/support](https://mongodb.com/support)

### **Common Commands Reference**
```bash
# Service management
net start MongoDB
net stop MongoDB
sc query MongoDB

# Database operations
mongosh
mongodump
mongorestore

# Logs and monitoring
type "C:\Program Files\MongoDB\Server\7.0\log\mongod.log"
```

---

**Remember**: MongoDB must be running before starting SecureTrainer!
