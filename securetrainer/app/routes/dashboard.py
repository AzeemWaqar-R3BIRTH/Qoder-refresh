# User dashboard & statistics
from flask import Blueprint, request, jsonify
from app.models.user_model import get_user_by_id, update_user_score_level

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/<user_id>', methods=['GET'])
def get_dashboard(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = {
        'username': user['username'],
        'full_name': f"{user['first_name']} {user['last_name']}",
        'department': user['department'],
        'score': user.get('score', 0),
        'level': user.get('level', 1),
        'role': user.get('role', 'Trainee'),
    }
    return jsonify({'dashboard': data}), 200
