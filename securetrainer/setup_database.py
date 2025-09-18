#!/usr/bin/env python3
"""
SecureTrainer Database Setup Script
This script helps you set up the MongoDB database and create required directories.
"""

import os
import sys
from pathlib import Path
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

def create_directories():
    """Create all required directories for the project."""
    print("📁 Creating required directories...")
    
    directories = [
        'logs',
        'qr_codes', 
        'backups',
        'model',
        'data'
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✅ Created: {directory}")
        else:
            print(f"✅ Already exists: {directory}")
    
    print()

def test_mongodb_connection():
    """Test MongoDB connection."""
    print("🔍 Testing MongoDB connection...")
    
    try:
        # Try to connect to MongoDB
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
        
        # Test the connection
        client.admin.command('ping')
        print("✅ MongoDB connection successful!")
        
        # Get MongoDB version
        version = client.admin.command('serverStatus')['version']
        print(f"📊 MongoDB version: {version}")
        
        client.close()
        return True
        
    except ConnectionFailure:
        print("❌ MongoDB connection failed!")
        print("💡 Make sure MongoDB service is running:")
        print("   net start MongoDB")
        return False
        
    except ServerSelectionTimeoutError:
        print("❌ MongoDB server not responding!")
        print("💡 Check if MongoDB is running on port 27017")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def setup_database():
    """Set up the SecureTrainer database and collections."""
    print("🗄️ Setting up SecureTrainer database...")
    
    try:
        # Connect to MongoDB
        client = MongoClient("mongodb://localhost:27017/")
        db = client.securetrainer
        
        # Create collections
        collections = [
            'users',
            'challenges',
            'challenge_attempts',
            'user_progress',
            'ai_models',
            'system_logs'
        ]
        
        for collection_name in collections:
            if collection_name not in db.list_collection_names():
                db.create_collection(collection_name)
                print(f"✅ Created collection: {collection_name}")
            else:
                print(f"✅ Collection exists: {collection_name}")
        
        # Create indexes for better performance
        print("\n📊 Creating database indexes...")
        
        # Users collection indexes
        db.users.create_index("email", unique=True)
        db.users.create_index("username", unique=True)
        db.users.create_index("department")
        db.users.create_index("score")
        print("✅ Users indexes created")
        
        # Challenges collection indexes
        db.challenges.create_index("category")
        db.challenges.create_index("difficulty")
        db.challenges.create_index("type")
        print("✅ Challenges indexes created")
        
        # Challenge attempts indexes
        db.challenge_attempts.create_index("user_id")
        db.challenge_attempts.create_index("challenge_id")
        db.challenge_attempts.create_index("timestamp")
        print("✅ Challenge attempts indexes created")
        
        # User progress indexes
        db.user_progress.create_index("user_id")
        db.user_progress.create_index("category")
        print("✅ User progress indexes created")
        
        client.close()
        print("\n🎉 Database setup completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        return False

def create_sample_data():
    """Create sample data for testing."""
    print("\n📝 Creating sample data...")
    
    try:
        client = MongoClient("mongodb://localhost:27017/")
        db = client.securetrainer
        
        # Check if sample data already exists
        if db.users.count_documents({}) > 0:
            print("✅ Sample data already exists")
            client.close()
            return True
        
        # Create sample user
        sample_user = {
            "username": "demo_user",
            "first_name": "Demo",
            "last_name": "User",
            "email": "demo@securetrainer.com",
            "company": "SecureTrainer Corp",
            "department": "IT",
            "score": 0,
            "level": 1,
            "role": "Trainee",
            "registration_date": "2024-01-01T00:00:00Z",
            "challenges_completed": 0,
            "success_rate": 0.0
        }
        
        db.users.insert_one(sample_user)
        print("✅ Sample user created")
        
        # Create sample challenge
        sample_challenge = {
            "id": "sql_injection_001",
            "category": "sql_injection",
            "difficulty": "beginner",
            "scenario": "Test a login form for SQL injection vulnerabilities",
            "question": "What payload would bypass authentication?",
            "payload": "' OR '1'='1' --",
            "hint": "Think about SQL operators and comments",
            "score_weight": 100,
            "type": "sql_injection"
        }
        
        db.challenges.insert_one(sample_challenge)
        print("✅ Sample challenge created")
        
        client.close()
        print("✅ Sample data created successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Sample data creation failed: {e}")
        return False

def verify_database():
    """Verify the database setup."""
    print("\n🔍 Verifying database setup...")
    
    try:
        client = MongoClient("mongodb://localhost:27017/")
        db = client.securetrainer
        
        # Check collections
        collections = db.list_collection_names()
        print(f"📚 Collections found: {len(collections)}")
        for collection in collections:
            count = db[collection].count_documents({})
            print(f"   - {collection}: {count} documents")
        
        # Check indexes
        print("\n📊 Database indexes:")
        for collection_name in ['users', 'challenges']:
            indexes = db[collection_name].list_indexes()
            print(f"   {collection_name}:")
            for index in indexes:
                print(f"     - {index['name']}: {index['key']}")
        
        client.close()
        print("\n✅ Database verification completed!")
        return True
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False

def main():
    """Main function."""
    print("🛡️ SecureTrainer Database Setup")
    print("=" * 50)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Step 1: Create directories
    create_directories()
    
    # Step 2: Test MongoDB connection
    if not test_mongodb_connection():
        print("\n❌ Cannot proceed without MongoDB connection")
        print("💡 Please ensure MongoDB is running and try again")
        return 1
    
    # Step 3: Setup database
    if not setup_database():
        print("\n❌ Database setup failed")
        return 1
    
    # Step 4: Create sample data
    create_sample_data()
    
    # Step 5: Verify setup
    verify_database()
    
    print("\n🎉 Database setup completed successfully!")
    print("\n📝 Next steps:")
    print("1. Create .env file: python create_env.py")
    print("2. Start the application: python start.py")
    print("3. Open MongoDB Compass to view your database")
    print("4. Access the platform: http://localhost:5000")
    
    return 0

if __name__ == '__main__':
    exit(main())
