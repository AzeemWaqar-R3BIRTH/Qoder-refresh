# Registration & QR login
from flask import Blueprint, request, jsonify, current_app
from app.utils.qr import QRCodeManager
from app.utils.email import EmailManager
from app.utils.security import hash_password
from app.models.user_model import insert_user

# Initialize managers
qr_manager = QRCodeManager()

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    required = ['first_name', 'last_name', 'username', 'email', 'password', 'company', 'department']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields'}), 400

    # Hash password
    hashed_pw = hash_password(data['password'])

    # Create user object
    user = {
        "first_name": data['first_name'],
        "last_name": data['last_name'],
        "username": data['username'],
        "email": data['email'],
        "password": hashed_pw,
        "company": data['company'],
        "department": data['department'],
        "score": 0,
        "level": 1,
        "role": "Trainee"
    }

    # Insert to DB
    uid = insert_user(user)

    # Generate login QR
    qr_data = qr_manager.generate_qr_code(uid, user['email'])

    # Email QR code
    try:
        from securetrainer import email_manager
        print(f"📧 Attempting to send email to {user['email']}")
        result = email_manager.send_welcome_email(user['email'], f"{user['first_name']} {user['last_name']}", qr_data)
        print(f"📧 Email send result: {result}")
    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        import traceback
        traceback.print_exc()

    return jsonify({'message': 'Registration successful. Check email for QR login.'}), 200
