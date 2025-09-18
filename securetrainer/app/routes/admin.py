from flask import Blueprint, request, jsonify
from app.models.challenge_model import add_challenge, delete_challenge, list_challenges
from app.models.analytics_model import get_challenge_logs
from app.models.user_model import promote_user
import os

admin_bp = Blueprint('admin', __name__)

# Simple token check for demo (replace with secure auth in production)
def is_admin(token):
    return token == os.getenv("ADMIN_TOKEN")

@admin_bp.route('/challenge', methods=['POST'])
def create_challenge():
    token = request.headers.get('Authorization')
    if not is_admin(token):
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    challenge_id = add_challenge(data)
    return jsonify({'message': 'Challenge added', 'id': challenge_id}), 201

@admin_bp.route('/challenge/<challenge_id>', methods=['DELETE'])
def remove_challenge(challenge_id):
    token = request.headers.get('Authorization')
    if not is_admin(token):
        return jsonify({'error': 'Unauthorized'}), 403

    delete_challenge(challenge_id)
    return jsonify({'message': 'Challenge deleted'}), 200

@admin_bp.route('/challenges', methods=['GET'])
def all_challenges():
    return jsonify({'challenges': list_challenges()}), 200

@admin_bp.route('/logs/<challenge_id>', methods=['GET'])
def view_logs(challenge_id):
    token = request.headers.get('Authorization')
    if not is_admin(token):
        return jsonify({'error': 'Unauthorized'}), 403

    logs = get_challenge_logs(challenge_id)
    return jsonify({'logs': logs}), 200

@admin_bp.route('/promote/<user_id>', methods=['POST'])
def promote(user_id):
    token = request.headers.get('Authorization')
    if not is_admin(token):
        return jsonify({'error': 'Unauthorized'}), 403

    new_role = request.json.get('role')
    promote_user(user_id, new_role)
    return jsonify({'message': f'User promoted to {new_role}'}), 200
