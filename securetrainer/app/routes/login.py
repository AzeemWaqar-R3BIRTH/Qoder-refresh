from flask import Blueprint, request, jsonify
from app.utils.qr import QRCodeManager
from app.models.user_model import get_user_by_id

# Initialize QR manager
qr_manager = QRCodeManager()

login_bp = Blueprint('login', __name__)


@login_bp.route('/login', methods=['POST'])
def login_with_qr():
    try:
        # Check if it's a file upload (from file input)
        if 'qr_image' in request.files:
            qr_image = request.files['qr_image']
            if qr_image.filename == '':
                return jsonify({'success': False, 'message': 'No file selected'}), 400
            
            print(f"Processing uploaded QR image: {qr_image.filename}")
            # Decode QR code from uploaded image
            success, result = qr_manager.validate_qr_code_from_image(qr_image)
            if not success:
                return jsonify({'success': False, 'message': result}), 400
            user_id = result['user_id']
            
        # Check if it's QR data from camera scanning
        elif request.is_json and 'qr_data' in request.json:
            qr_data = request.json['qr_data']
            print(f"Processing QR data from camera: {qr_data[:50]}...")
            # Decode QR code from scanned data
            success, result = qr_manager.validate_qr_code(qr_data)
            if not success:
                return jsonify({'success': False, 'message': result}), 400
            user_id = result['user_id']
            
        else:
            return jsonify({'success': False, 'message': 'No QR code data provided'}), 400

        print(f"Decoded QR user_id: {user_id}")

        if not user_id:
            print("ERROR: Invalid or unreadable QR code")
            return jsonify({'success': False, 'message': 'Invalid or unreadable QR code'}), 400

        user = get_user_by_id(user_id)
        print(f"Found user: {user}")

        if not user:
            print(f"ERROR: User not found for ID {user_id}")
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Return public user data
        user_data = {
            "_id": str(user.get('_id', user_id)),
            "user_id": str(user_id),
            "username": user['username'],
            "name": f"{user['first_name']} {user['last_name']}",
            "department": user['department'],
            "level": user.get('level', 1),
            "score": user.get('score', 0),
            "role": user.get('role', 'Trainee')
        }

        return jsonify({'success': True, 'message': 'Login successful', 'user': user_data}), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500
