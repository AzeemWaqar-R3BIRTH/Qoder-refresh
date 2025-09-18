# 🗄️ Database Setup Guide for SecureTrainer

## 🚀 **Quick Setup (Recommended)**

### **Option 1: Automated Setup**
```bash
cd securetrainer
python setup_database.py
```

### **Option 2: Manual Setup**
Follow the detailed steps below.

## 📋 **Prerequisites**

- ✅ MongoDB installed and running
- ✅ MongoDB Compass installed
- ✅ Python with pymongo package
- ✅ SecureTrainer project files

## 🔧 **Step-by-Step Database Setup**

### **Step 1: Start MongoDB Service**
```bash
# Open Command Prompt as Administrator
net start MongoDB

# Verify service is running
sc query MongoDB
```

### **Step 2: Create Project Directories**
```bash
cd securetrainer
mkdir logs
mkdir qr_codes
mkdir backups
mkdir model
mkdir data
```

### **Step 3: Install Python Dependencies**
```bash
# Install pymongo if not already installed
pip install pymongo

# Or install all requirements
pip install -r requirements.txt
```

### **Step 4: Run Database Setup Script**
```bash
python setup_database.py
```

## 🗂️ **Database Structure**

### **Collections Created**

#### **1. Users Collection**
```json
{
  "_id": "ObjectId",
  "username": "string (unique)",
  "first_name": "string",
  "last_name": "string",
  "email": "string (unique)",
  "password_hash": "string",
  "company": "string",
  "department": "string",
  "score": "number",
  "level": "number",
  "role": "string",
  "registration_date": "date",
  "challenges_completed": "number",
  "success_rate": "number",
  "hint_count": "number"
}
```

#### **2. Challenges Collection**
```json
{
  "_id": "ObjectId",
  "id": "string (unique)",
  "category": "string",
  "difficulty": "string",
  "scenario": "string",
  "question": "string",
  "payload": "string",
  "hint": "string",
  "score_weight": "number",
  "type": "string"
}
```

#### **3. Challenge Attempts Collection**
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "challenge_id": "string",
  "answer": "string",
  "is_correct": "boolean",
  "score_earned": "number",
  "hints_used": "number",
  "completion_time": "number",
  "timestamp": "date"
}
```

#### **4. User Progress Collection**
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "category": "string",
  "challenges_completed": "number",
  "total_score": "number",
  "best_score": "number",
  "last_attempt": "date"
}
```

#### **5. AI Models Collection**
```json
{
  "_id": "ObjectId",
  "model_name": "string",
  "version": "string",
  "file_path": "string",
  "accuracy": "number",
  "last_updated": "date",
  "parameters": "object"
}
```

#### **6. System Logs Collection**
```json
{
  "_id": "ObjectId",
  "level": "string",
  "message": "string",
  "timestamp": "date",
  "user_id": "ObjectId (optional)",
  "action": "string",
  "details": "object"
}
```

### **Database Indexes**

#### **Performance Indexes**
- **Users**: `email`, `username`, `department`, `score`
- **Challenges**: `category`, `difficulty`, `type`
- **Attempts**: `user_id`, `challenge_id`, `timestamp`
- **Progress**: `user_id`, `category`

## 🧪 **Testing Your Database**

### **Test 1: Basic Connection**
```bash
# Connect to MongoDB
mongosh

# Switch to SecureTrainer database
use securetrainer

# List collections
show collections

# Check document counts
db.users.countDocuments()
db.challenges.countDocuments()

# Exit
exit
```

### **Test 2: Python Connection**
```python
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client.securetrainer

# Test basic operations
print(f"Database: {db.name}")
print(f"Collections: {db.list_collection_names()}")

# Check users
users_count = db.users.count_documents({})
print(f"Users: {users_count}")

# Check challenges
challenges_count = db.challenges.count_documents({})
print(f"Challenges: {challenges_count}")

client.close()
```

### **Test 3: Sample Data Verification**
```bash
# In MongoDB shell
use securetrainer

# Check sample user
db.users.findOne({username: "demo_user"})

# Check sample challenge
db.challenges.findOne({id: "sql_injection_001"})
```

## 📊 **MongoDB Compass Setup**

### **Step 1: Open MongoDB Compass**
1. **Launch** MongoDB Compass
2. **Click** "New Connection"

### **Step 2: Connect to Database**
1. **Connection String**: `mongodb://localhost:27017/`
2. **Click** "Connect"

### **Step 3: Navigate to SecureTrainer**
1. **Click** on `securetrainer` database
2. **Explore** collections
3. **View** sample data

### **Step 4: Monitor Database**
- **Real-time** document counts
- **Query** data interactively
- **Monitor** performance

## 🔍 **Database Verification Commands**

### **Check Collections**
```bash
# In MongoDB shell
use securetrainer
show collections

# Expected output:
# - users
# - challenges
# - challenge_attempts
# - user_progress
# - ai_models
# - system_logs
```

### **Check Indexes**
```bash
# Check users indexes
db.users.getIndexes()

# Check challenges indexes
db.challenges.getIndexes()
```

### **Check Sample Data**
```bash
# Count documents in each collection
db.users.countDocuments()
db.challenges.countDocuments()
db.challenge_attempts.countDocuments()
db.user_progress.countDocuments()
db.ai_models.countDocuments()
db.system_logs.countDocuments()
```

## 🚨 **Troubleshooting**

### **Common Issues**

#### **1. "Connection refused"**
```bash
# Check if MongoDB is running
net start MongoDB

# Check port 27017
netstat -ano | findstr :27017
```

#### **2. "Database not found"**
```bash
# Create database manually
mongosh
use securetrainer
db.createCollection("users")
```

#### **3. "Permission denied"**
- **Run Command Prompt as Administrator**
- **Check MongoDB service permissions**
- **Verify data directory permissions**

#### **4. "Collection already exists"**
- This is normal - the script handles existing collections
- No action needed

### **Reset Database (if needed)**
```bash
# Drop and recreate database
mongosh
use securetrainer
db.dropDatabase()
exit

# Run setup script again
python setup_database.py
```

## 📈 **Performance Optimization**

### **Index Strategy**
- **Unique indexes** on email and username
- **Compound indexes** for common queries
- **Text indexes** for search functionality

### **Memory Settings**
```bash
# MongoDB configuration
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

## 🔒 **Security Considerations**

### **Development Environment**
- **Bind IP**: `127.0.0.1` (localhost only)
- **Authentication**: Disabled
- **Network**: Local access only

### **Production Environment**
- **Enable Authentication**: Create admin users
- **Network Security**: Restrict access
- **SSL/TLS**: Enable encryption
- **Regular Backups**: Automated backup strategy

## 🎯 **Next Steps**

1. **✅ Database Setup**: `python setup_database.py`
2. **📝 Environment**: `python create_env.py`
3. **🚀 Launch App**: `python start.py`
4. **🌐 Access**: `http://localhost:5000`

## 📞 **Need Help?**

### **MongoDB Resources**
- **Documentation**: [docs.mongodb.com](https://docs.mongodb.com)
- **Compass Guide**: [docs.mongodb.com/compass](https://docs.mongodb.com/compass)
- **Community**: [community.mongodb.com](https://community.mongodb.com)

### **Common Commands Reference**
```bash
# Service management
net start MongoDB
net stop MongoDB
sc query MongoDB

# Database operations
mongosh
use securetrainer
show collections
show dbs

# Collection operations
db.users.find()
db.users.countDocuments()
db.users.findOne({username: "demo_user"})
```

---

**Remember**: A properly configured database is essential for SecureTrainer to function correctly!
