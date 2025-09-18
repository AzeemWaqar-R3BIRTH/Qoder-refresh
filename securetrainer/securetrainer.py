#!/usr/bin/env python3
"""
SecureTrainer - Cybersecurity Awareness Training Platform
Final Year Project for Bachelor's in Cyber Security

A comprehensive web application that provides interactive cybersecurity training
through gamified challenges including SQL injection, XSS, command injection,
and more. Features AI-driven difficulty adjustment and QR code authentication.
"""

import os
import sys
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, make_response
from flask_mail import Mail, Message
from flask_cors import CORS
import bcrypt
import qrcode
from PIL import Image
import io
import base64
import uuid
import json
from dotenv import load_dotenv

# Load environment variables
try:
    load_dotenv()
except Exception as e:
    print(f"Warning: Could not load .env file: {e}")
    print("Using default environment variables...")

# Import our modules
from app.models.user_model import (
    get_db, insert_user, get_user_by_id, update_user_score_level, 
    get_top_users, get_user_rank, promote_user
)
from app.models.challenge_model import (
    add_challenge, delete_challenge, list_challenges, load_sql_challenges,
    get_fallback_sql_challenges, get_xss_challenges, get_command_injection_challenges,
    get_authentication_challenges, get_csrf_challenges, get_all_challenges,
    get_challenges_by_category, get_random_challenge, get_challenge_by_id,
    get_challenges_by_difficulty, get_user_appropriate_challenges, get_challenge_statistics
)
from app.utils.qr import QRCodeManager
from app.utils.email import EmailManager
from robust_email_manager import RobustEmailManager

# Set default environment variables if .env fails to load
if not os.getenv('SECRET_KEY'):
    os.environ['SECRET_KEY'] = 'Azeem and Saffan Developed this AI Driven Cyber Security Training Application in Supervision of Dr Shahbaz Siddiqui and Dr Fahad Samad'
if not os.getenv('MONGO_URI'):
    os.environ['MONGO_URI'] = 'mongodb://localhost:27017/securetrainer'
if not os.getenv('MAIL_SERVER'):
    os.environ['MAIL_SERVER'] = 'smtp.gmail.com'
if not os.getenv('MAIL_PORT'):
    os.environ['MAIL_PORT'] = '587'
if not os.getenv('MAIL_USERNAME'):
    os.environ['MAIL_USERNAME'] = 'azeemwaqar.work@gmail.com'
if not os.getenv('MAIL_PASSWORD'):
    os.environ['MAIL_PASSWORD'] = 'wmwb ejkp sevx ipap'
if not os.getenv('MAIL_USE_TLS'):
    os.environ['MAIL_USE_TLS'] = 'True'
if not os.getenv('ADMIN_TOKEN'):
    os.environ['ADMIN_TOKEN'] = 'supersecretadmintoken123'

# Initialize Flask app
app = Flask(__name__, 
           template_folder='app/templates',
           static_folder='app/static')
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Configuration
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True') == 'True',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MONGO_URI=os.getenv('MONGO_URI', 'mongodb://localhost:27017/securetrainer'),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Initialize Flask-Mail
mail = Mail(app)

# Initialize CORS
CORS(app)

# Initialize MongoDB
try:
    from pymongo import MongoClient
    mongo_client = MongoClient(app.config['MONGO_URI'])
    db = mongo_client.securetrainer
    print("✅ Connected to MongoDB")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    db = None

# Initialize managers
qr_manager = QRCodeManager()
email_manager = EmailManager(mail)
robust_email_manager = RobustEmailManager()

# AI Model fallbacks (simplified versions for demo)
def analyze_user_learning_patterns(user): 
    return {
        'preferred_challenge_types': ['sql_injection', 'xss'],
        'learning_style': 'visual',
        'difficulty_preference': 'intermediate'
    }

def generate_adaptive_hint(user, challenge, attempt_count): 
    hints = [
        "Try thinking about how the application processes your input.",
        "Consider what happens when special characters are used.",
        "Look for ways to break out of the expected input format.",
        "Think about database query construction.",
        "Consider how the application handles different data types."
    ]
    return hints[min(attempt_count, len(hints) - 1)]

def predict_user_success_probability(user, challenge): 
    # Simple probability based on user level and challenge difficulty
    user_level = user.get('level', 1)
    challenge_difficulty = challenge.get('difficulty', 1)
    return max(0.1, min(0.9, 0.5 + (user_level - challenge_difficulty) * 0.1))

# Helper functions
def set_user_session(user):
    """Set user session data consistently."""
    session['user_id'] = str(user['_id'])
    session['username'] = user['username']
    session.permanent = True
    session.modified = True
    # Force session to be saved
    session.get('user_id')  # This forces the session to be marked as modified
    print(f"🔐 Session set: user_id={session['user_id']}, username={session['username']}")
    print(f"🔐 Session data: {dict(session)}")

def get_user_from_session():
    """Get user data from session."""
    print(f"🔍 Getting user from session: {dict(session)}")
    if 'user_id' in session and db is not None:
        from bson import ObjectId
        try:
            # Try ObjectId conversion first
            user_id = ObjectId(session['user_id'])
            user = db.users.find_one({'_id': user_id})
            print(f"🔍 User found with ObjectId: {user}")
            return user
        except Exception as e:
            print(f"🔍 ObjectId conversion failed: {e}, trying string")
            # Fallback to string
            user = db.users.find_one({'_id': session['user_id']})
            print(f"🔍 User found with string: {user}")
            return user
    print(f"🔍 No user_id in session or db is None")
    return None

def require_auth(f):
    """Decorator to require authentication."""
    def decorated_function(*args, **kwargs):
        print(f"🔍 require_auth checking session: {dict(session)}")
        user = get_user_from_session()
        if not user:
            print("❌ require_auth: No user found, redirecting to login")
            return redirect('/login')
        print(f"✅ require_auth: User found: {user.get('username', 'Unknown')}")
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Routes
@app.route('/')
def index():
    """Redirect root to login to ensure the correct template is served."""
    return redirect('/login')

@app.route('/login.html')
def login_html_alias():
    """Handle accidental visits to /login.html by redirecting to /login."""
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        try:
            # Get form data
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            company = request.form.get('company')
            department = request.form.get('department')
            
            # Validate required fields
            if not all([first_name, last_name, username, email, password, company, department]):
                flash('All fields are required.', 'error')
                return render_template('register.html')
            
            # Check if user already exists
            if db is not None and db.users.find_one({'$or': [{'username': username}, {'email': email}]}):
                flash('Username or email already exists.', 'error')
                return render_template('register.html')
            
            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Create user
            user_data = {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'email': email,
                'password': hashed_password,
                'company': company,
                'department': department,
                'level': 1,
                'score': 0,
                'role': 'Trainee',
                'created_at': datetime.now(),
                'last_login': None,
                'challenges_completed': [],
                'achievements': []
            }
            
            if db is not None:
                result = db.users.insert_one(user_data)
                user_id = result.inserted_id
                
                # Generate QR code
                qr_data = qr_manager.generate_qr_code(str(user_id), email)
                
                # Send welcome email with QR code (non-blocking)
                try:
                    # Send email in background to avoid blocking registration
                    import threading
                    def send_email_async():
                        try:
                            robust_email_manager.send_welcome_email(email, f"{first_name} {last_name}", qr_data)
                            print(f"✅ Welcome email sent to {email}")
                        except Exception as e:
                            print(f"⚠️ Failed to send email: {e}")
                    
                    # Start email sending in background thread
                    email_thread = threading.Thread(target=send_email_async)
                    email_thread.daemon = True
                    email_thread.start()
                    print(f"📧 Email sending started in background for {email}")
                except Exception as e:
                    print(f"⚠️ Failed to start email sending: {e}")
                
                flash('Registration successful! Check your email for your QR code.', 'success')
                return redirect('/login')
            else:
                flash('Database connection failed. Please try again.', 'error')
            
        except Exception as e:
            print(f"Registration error: {e}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """API endpoint for user registration."""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'username', 'email', 'password', 'company', 'department']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Check if user already exists
        if db is not None and db.users.find_one({'$or': [{'username': data['username']}, {'email': data['email']}]}):
            return jsonify({'error': 'Username or email already exists'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        
        # Create user
        user_data = {
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'username': data['username'],
            'email': data['email'],
            'password': hashed_password,
            'company': data['company'],
            'department': data['department'],
            'level': 1,
            'score': 0,
            'role': 'Trainee',
            'created_at': datetime.now(),
            'last_login': None,
            'challenges_completed': [],
            'achievements': []
        }
        
        if db is not None:
            result = db.users.insert_one(user_data)
            user_id = result.inserted_id
            
            # Generate QR code
            qr_data = qr_manager.generate_qr_code(str(user_id), data['email'])
            
            # Send welcome email with QR code (non-blocking)
            try:
                # Send email in background to avoid blocking registration
                import threading
                def send_email_async():
                    try:
                        robust_email_manager.send_welcome_email(data['email'], f"{data['first_name']} {data['last_name']}", qr_data)
                        print(f"✅ Welcome email sent to {data['email']}")
                    except Exception as e:
                        print(f"⚠️ Failed to send email: {e}")
                
                # Start email sending in background thread
                email_thread = threading.Thread(target=send_email_async)
                email_thread.daemon = True
                email_thread.start()
                print(f"📧 Email sending started in background for {data['email']}")
            except Exception as e:
                print(f"⚠️ Failed to start email sending: {e}")
            
            return jsonify({
                'success': True,
                'message': 'Registration successful! Check your email for your QR code.',
                'user_id': str(user_id),
                'redirect_url': '/login'
            }), 200
        else:
            return jsonify({'error': 'Database connection failed'}), 500
        
    except Exception as e:
        print(f"API registration error: {e}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """QR code login page."""
    if request.method == 'POST':
        try:
            # Handle QR code upload
            if 'qr_image' in request.files:
                file = request.files['qr_image']
                if file.filename:
                    # Process uploaded QR code
                    is_valid, user_data = qr_manager.validate_qr_code_from_image(file)
                    if is_valid and db is not None:
                        from bson import ObjectId
                        try:
                            user_id = ObjectId(user_data['user_id'])
                            user = db.users.find_one({'_id': user_id})
                        except:
                            user = db.users.find_one({'_id': user_data['user_id']})
                        
                        if user:
                            set_user_session(user)
                            flash('Login successful!', 'success')
                            return redirect('/dashboard')
                    flash('Invalid QR code. Please try again.', 'error')
            
            # Handle manual QR code input
            qr_data = request.form.get('qr_data')
            if qr_data:
                # Validate QR code data
                is_valid, user_data = qr_manager.validate_qr_code(qr_data)
                if is_valid and db is not None:
                        from bson import ObjectId
                        try:
                            user_id = ObjectId(user_data['user_id'])
                            user = db.users.find_one({'_id': user_id})
                        except:
                            user = db.users.find_one({'_id': user_data['user_id']})
                        
                        if user:
                            set_user_session(user)
                            flash('Login successful!', 'success')
                            return redirect(url_for('dashboard'))
                
                flash('Invalid QR code. Please try again.', 'error')
        
        except Exception as e:
            print(f"Login error: {e}")
            flash('Login failed. Please try again.', 'error')
    
    response = make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API endpoint for user login."""
    print(f"🔍 API login called - Method: {request.method}")
    print(f"🔍 Content-Type: {request.content_type}")
    print(f"🔍 Request files: {list(request.files.keys())}")
    print(f"🔍 Request form: {dict(request.form)}")
    
    try:
        # Handle QR code image upload
        if 'qr_image' in request.files:
            file = request.files['qr_image']
            if file.filename:
                print(f"📁 Processing QR image: {file.filename}")
                # Reset file pointer to beginning
                file.seek(0)
                
                is_valid, result = qr_manager.validate_qr_code_from_image(file)
                print(f"🔍 QR validation result: valid={is_valid}, result={result}")
                
                if is_valid and db is not None:
                    user_data = result  # result contains user_data when valid
                    print(f"🔍 User data from QR: {user_data}")
                    
                    # Try to find user by ID
                    user = None
                    user_id_str = str(user_data['user_id'])
                    
                    # Try ObjectId first
                    try:
                        from bson import ObjectId
                        if ObjectId.is_valid(user_id_str):
                            user_id = ObjectId(user_id_str)
                            user = db.users.find_one({'_id': user_id})
                            print(f"🔍 User found with ObjectId: {user is not None}")
                    except Exception as e:
                        print(f"🔍 ObjectId lookup failed: {e}")
                    
                    # If not found, try as string
                    if not user:
                        user = db.users.find_one({'_id': user_id_str})
                        print(f"🔍 User found with string ID: {user is not None}")
                    
                    if user:
                        print(f"🔍 Found user: {user['username']}")
                        set_user_session(user)
                        
                        # Update last login
                        db.users.update_one(
                            {'_id': user['_id']},
                            {'$set': {'last_login': datetime.now()}}
                        )
                        
                        return jsonify({
                            'success': True,
                            'message': 'Login successful!',
                            'redirect_url': '/dashboard',
                            'user': {
                                'id': str(user['_id']),
                                'username': user['username'],
                                'email': user['email'],
                                'level': user.get('level', 1),
                                'role': user.get('role', 'Trainee')
                            }
                        }), 200
                    else:
                        print(f"❌ User not found for ID: {user_id_str}")
                        return jsonify({'success': False, 'message': 'User not found'}), 404
                else:
                    error_msg = result if isinstance(result, str) else 'Invalid QR code'
                    print(f"❌ QR validation failed: {error_msg}")
                    return jsonify({'success': False, 'message': error_msg}), 400
            else:
                return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        # Handle QR code data from camera
        elif request.is_json:
            data = request.get_json()
            if data and 'qr_data' in data:
                qr_data = data['qr_data']
                print(f"📱 Processing camera QR data: {qr_data[:100]}...")
                
                is_valid, result = qr_manager.validate_qr_code(qr_data)
                print(f"🔍 Camera QR validation result: valid={is_valid}, result={result}")
                
                if is_valid and db is not None:
                    user_data = result  # result contains user_data when valid
                    print(f"🔍 User data from camera QR: {user_data}")
                    
                    # Try to find user by ID
                    user = None
                    user_id_str = str(user_data['user_id'])
                    
                    # Try ObjectId first
                    try:
                        from bson import ObjectId
                        if ObjectId.is_valid(user_id_str):
                            user_id = ObjectId(user_id_str)
                            user = db.users.find_one({'_id': user_id})
                    except Exception as e:
                        print(f"🔍 ObjectId lookup failed: {e}")
                    
                    # If not found, try as string
                    if not user:
                        user = db.users.find_one({'_id': user_id_str})
                    
                    if user:
                        print(f"🔍 Found user: {user['username']}")
                        set_user_session(user)
                        
                        # Update last login
                        db.users.update_one(
                            {'_id': user['_id']},
                            {'$set': {'last_login': datetime.now()}}
                        )
                        
                        return jsonify({
                            'success': True,
                            'message': 'Login successful!',
                            'redirect_url': '/dashboard',
                            'user': {
                                'id': str(user['_id']),
                                'username': user['username'],
                                'email': user['email'],
                                'level': user.get('level', 1),
                                'role': user.get('role', 'Trainee')
                            }
                        }), 200
                    else:
                        print(f"❌ User not found for ID: {user_id_str}")
                        return jsonify({'success': False, 'message': 'User not found'}), 404
                else:
                    error_msg = result if isinstance(result, str) else 'Invalid QR code'
                    print(f"❌ Camera QR validation failed: {error_msg}")
                    return jsonify({'success': False, 'message': error_msg}), 400
            else:
                return jsonify({'success': False, 'message': 'No QR data provided in JSON request'}), 400
        else:
            return jsonify({'success': False, 'message': 'Invalid request format. Expected file upload or JSON data.'}), 400
        
    except Exception as e:
        print(f"❌ API login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500

@app.route('/demo-login')
def demo_login():
    """Demo login for testing purposes."""
    try:
        if db is not None:
            # Find or create a demo user
            demo_user = db.users.find_one({'username': 'demo_user'})
            if not demo_user:
                # Create demo user
                demo_user_data = {
                    'first_name': 'Demo',
                    'last_name': 'User',
                    'username': 'demo_user',
                    'email': 'demo@securetrainer.com',
                    'password': bcrypt.hashpw('demo123'.encode('utf-8'), bcrypt.gensalt()),
                    'company': 'SecureTrainer',
                    'department': 'IT',
                    'level': 5,
                    'score': 2500,
                    'role': 'Senior Analyst',
                    'created_at': datetime.now(),
                    'last_login': datetime.now(),
                    'challenges_completed': [],
                    'achievements': ['Fast Learner', 'SQL Master', 'XSS Defender']
                }
                result = db.users.insert_one(demo_user_data)
                demo_user = demo_user_data
                demo_user['_id'] = result.inserted_id
            
            set_user_session(demo_user)
            flash('Demo login successful!', 'success')
            return redirect('/dashboard')
        else:
            flash('Database not available for demo login.', 'error')
            return redirect('/login')
    except Exception as e:
        print(f"Demo login error: {e}")
        flash('Demo login failed.', 'error')
        return redirect('/login')

@app.route('/dashboard')
@require_auth
def dashboard():
    """User dashboard."""
    print(f"🏠 Dashboard accessed - session: {dict(session)}")
    user = get_user_from_session()
    print(f"👤 User from session: {user}")
    if not user:
        print("❌ No user found, redirecting to login")
        return redirect('/login')
    
    # Get user statistics
    stats = {
        'total_challenges': len(user.get('challenges_completed', [])),
        'current_level': user.get('level', 1),
        'total_score': user.get('score', 0),
        'role': user.get('role', 'Trainee'),
        'achievements': user.get('achievements', [])
    }
    
    print(f"📊 Dashboard stats: {stats}")
    return render_template('dashboard.html', user=user, stats=stats)

@app.route('/challenges')
@require_auth
def challenges():
    """Challenges page."""
    user = get_user_from_session()
    if not user:
        return redirect('/login')
    
    # Get available challenges
    available_challenges = []
    if db is not None:
        challenges_cursor = db.challenges.find({'level': {'$lte': user.get('level', 1) + 2}})
        available_challenges = list(challenges_cursor)
    
    return render_template('challenges.html', user=user, challenges=available_challenges)

@app.route('/api/challenges/start', methods=['POST'])
@require_auth
def start_challenge():
    """Start a challenge."""
    try:
        data = request.get_json()
        challenge_id = data.get('challenge_id')
        
        if not challenge_id or db is None:
            return jsonify({'error': 'Invalid challenge ID'}), 400
        
        challenge = db.challenges.find_one({'_id': challenge_id})
        if not challenge:
            return jsonify({'error': 'Challenge not found'}), 404
        
        # Add challenge to user's active challenges
        user = get_user_from_session()
        if 'active_challenges' not in user:
            user['active_challenges'] = []
        
        if challenge_id not in user['active_challenges']:
            user['active_challenges'].append(challenge_id)
            db.users.update_one(
                {'_id': user['_id']}, 
                {'$set': {'active_challenges': user['active_challenges']}}
            )
        
        return jsonify({
            'success': True,
            'challenge': {
                'id': str(challenge['_id']),
                'title': challenge['title'],
                'description': challenge['description'],
                'difficulty': challenge['difficulty'],
                'points': challenge['points'],
                'category': challenge['category']
            }
        }), 200
        
    except Exception as e:
        print(f"Start challenge error: {e}")
        return jsonify({'error': 'Failed to start challenge'}), 500

@app.route('/api/challenges/submit', methods=['POST'])
@require_auth
def submit_challenge():
    """Submit challenge solution."""
    try:
        data = request.get_json()
        challenge_id = data.get('challenge_id')
        solution = data.get('solution')
        
        if not challenge_id or not solution or db is None:
            return jsonify({'error': 'Invalid submission'}), 400
        
        challenge = db.challenges.find_one({'_id': challenge_id})
        if not challenge:
            return jsonify({'error': 'Challenge not found'}), 404
        
        user = get_user_from_session()
        
        # Simple solution validation (in production, this would be more sophisticated)
        is_correct = solution.lower() in challenge.get('expected_solutions', [])
        
        if is_correct:
            # Award points
            points_earned = challenge.get('points', 10)
            new_score = user.get('score', 0) + points_earned
            new_level = (new_score // 1000) + 1
            
            # Update user
            db.users.update_one(
                {'_id': user['_id']},
                {
                    '$inc': {'score': points_earned},
                    '$set': {'level': new_level},
                    '$addToSet': {'challenges_completed': challenge_id}
                }
            )
            
            return jsonify({
                'success': True,
                'correct': True,
                'points_earned': points_earned,
                'new_score': new_score,
                'new_level': new_level
            }), 200
        else:
            return jsonify({
                'success': True,
                'correct': False,
                'message': 'Incorrect solution. Try again!'
            }), 200
        
    except Exception as e:
        print(f"Submit challenge error: {e}")
        return jsonify({'error': 'Failed to submit solution'}), 500

@app.route('/api/challenges/hint', methods=['POST'])
@require_auth
def get_hint():
    """Get hint for a challenge."""
    try:
        data = request.get_json()
        challenge_id = data.get('challenge_id')
        
        if not challenge_id or db is None:
            return jsonify({'error': 'Invalid challenge ID'}), 400
        
        challenge = db.challenges.find_one({'_id': challenge_id})
        if not challenge:
            return jsonify({'error': 'Challenge not found'}), 404
        
        user = get_user_from_session()
        attempt_count = data.get('attempt_count', 0)
        
        # Generate adaptive hint
        hint = generate_adaptive_hint(user, challenge, attempt_count)
        
        return jsonify({
            'success': True,
            'hint': hint
        }), 200
        
    except Exception as e:
        print(f"Get hint error: {e}")
        return jsonify({'error': 'Failed to get hint'}), 500

@app.route('/api/ai/recommendations', methods=['GET'])
@require_auth
def get_ai_recommendations():
    """Get AI-powered challenge recommendations."""
    try:
        user = get_user_from_session()
        if not user or db is None:
            return jsonify({'error': 'User not found'}), 404
        
        # Analyze user learning patterns
        patterns = analyze_user_learning_patterns(user)
        
        # Get recommended challenges
        recommended_challenges = []
        if db is not None:
            challenges_cursor = db.challenges.find({
                'level': {'$lte': user.get('level', 1) + 1},
                'category': {'$in': patterns.get('preferred_challenge_types', [])}
            }).limit(5)
            recommended_challenges = list(challenges_cursor)
        
        return jsonify({
            'success': True,
            'recommendations': recommended_challenges,
            'patterns': patterns
        }), 200
        
    except Exception as e:
        print(f"AI recommendations error: {e}")
        return jsonify({'error': 'Failed to get recommendations'}), 500

@app.route('/api/challenges/list', methods=['GET'])
@require_auth
def list_challenges_api():
    """List all available challenges."""
    try:
        challenges = get_all_challenges()
        return jsonify({
            'success': True,
            'challenges': challenges
        }), 200
    except Exception as e:
        print(f"Error listing challenges: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load challenges'
        }), 500

@app.route('/api/challenges/<challenge_id>', methods=['GET'])
@require_auth
def get_challenge_api(challenge_id):
    """Get a specific challenge by ID."""
    try:
        challenge = get_challenge_by_id(challenge_id)
        if challenge:
            return jsonify({
                'success': True,
                'challenge': challenge
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Challenge not found'
            }), 404
    except Exception as e:
        print(f"Error getting challenge: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load challenge'
        }), 500

@app.route('/api/challenges/category/<category>', methods=['GET'])
@require_auth
def get_challenges_by_category_api(category):
    """Get challenges by category."""
    try:
        challenges = get_challenges_by_category(category)
        return jsonify({
            'success': True,
            'challenges': challenges
        }), 200
    except Exception as e:
        print(f"Error getting challenges by category: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load challenges'
        }), 500

@app.route('/api/challenges/difficulty/<difficulty>', methods=['GET'])
@require_auth
def get_challenges_by_difficulty_api(difficulty):
    """Get challenges by difficulty level."""
    try:
        challenges = get_challenges_by_difficulty(difficulty)
        return jsonify({
            'success': True,
            'challenges': challenges
        }), 200
    except Exception as e:
        print(f"Error getting challenges by difficulty: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load challenges'
        }), 500

@app.route('/api/user/stats', methods=['GET'])
@require_auth
def get_user_stats():
    """Get user statistics."""
    try:
        user = get_user_from_session()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        stats = {
            'username': user['username'],
            'level': user.get('level', 1),
            'score': user.get('score', 0),
            'role': user.get('role', 'Trainee'),
            'challenges_completed': len(user.get('challenges_completed', [])),
            'achievements': user.get('achievements', []),
            'department': user.get('department', 'Unknown'),
            'company': user.get('company', 'Unknown')
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        print(f"Get user stats error: {e}")
        return jsonify({'error': 'Failed to get user stats'}), 500

@app.route('/logout')
def logout():
    """Logout user."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/login')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'database': 'connected' if db is not None else 'disconnected'
    })

if __name__ == '__main__':
    # Clean up expired QR codes
    qr_manager.cleanup_expired_codes()
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print("🚀 Starting SecureTrainer...")
    print(f"📍 Port: {port}")
    print(f"🔧 Debug: {debug}")
    print(f"📧 Mail: {app.config['MAIL_USERNAME']}")
    print(f"🗄️ Database: {'Connected' if db is not None else 'Disconnected'}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)