from flask import Blueprint, jsonify, request
from app.models.user_model import get_top_users, get_user_rank

leaderboard_bp = Blueprint('leaderboard', __name__)

@leaderboard_bp.route('/global', methods=['GET'])
def global_leaderboard():
    top_users = get_top_users()
    return jsonify({'leaderboard': top_users}), 200

@leaderboard_bp.route('/department/<dept>', methods=['GET'])
def department_leaderboard(dept):
    top_users = get_top_users(department=dept)
    return jsonify({'leaderboard': top_users}), 200

@leaderboard_bp.route('/rank/<user_id>', methods=['GET'])
def user_rank(user_id):
    rank_info = get_user_rank(user_id)
    return jsonify(rank_info), 200
