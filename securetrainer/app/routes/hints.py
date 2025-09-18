from flask import Blueprint, jsonify, request
from app.models.analytics_model import log_event

hints_bp = Blueprint('hints', __name__)

@hints_bp.route('/get/<challenge_id>', methods=['GET'])
def get_hint(challenge_id):
    hint_level = request.args.get('level', default=1, type=int)

    # Expanded hints for SQL injection
    hints = {
        "sql-injection": [
            "Look for input fields where data is likely retrieved from a database.",
            "Try entering a single quote (') to see if it causes an error.",
            "Common SQL injection patterns include: ' OR '1'='1, ' OR 1=1 --, and UNION SELECT statements.",
            "For UNION attacks, you need to match the number of columns in the original query.",
            "Blind SQL injection requires boolean conditions that affect the application's response.",
            "Use comments (-- or #) to ignore the rest of the SQL query.",
            "UNION SELECT can extract data from other tables when you know their structure.",
            "Try extracting database schema information using information_schema tables."
        ],
        # Other challenge types can be added here
        "xss": [
            "Try injecting basic script tags. ",
            "Test input inside HTML context. ",
            "Use console.log to debug script placement."
        ]
    }

    challenge_type = challenge_id.lower().replace(" ", "-")
    selected_hints = hints.get(challenge_type, ["No hints available"])
    hint_text = selected_hints[min(hint_level - 1, len(selected_hints) - 1)]

    # Log hint request
    user_id = request.args.get('user_id')
    if user_id:
        log_event(user_id, challenge_id, "hint", {"level": hint_level})

    return jsonify({'text': hint_text}), 200
