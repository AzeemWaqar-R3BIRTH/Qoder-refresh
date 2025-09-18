from flask import current_app
from datetime import datetime

def log_event(user_id, challenge_id, event_type, metadata=None):
    db = current_app.config['MONGO_CLIENT'].get_database()
    log = {
        'user_id': user_id,
        'challenge_id': challenge_id,
        'event_type': event_type,
        'metadata': metadata or {},
        'timestamp': datetime.utcnow()
    }
    db.analytics.insert_one(log)

def get_challenge_logs(challenge_id):
    db = current_app.config['MONGO_CLIENT'].get_database()
    logs = db.analytics.find({'challenge_id': challenge_id})
    return [{
        'user_id': log['user_id'],
        'event': log['event_type'],
        'meta': log['metadata'],
        'time': log['timestamp']
    } for log in logs]

def export_analytics_for_csv():
    db = current_app.config['MONGO_CLIENT'].get_database()
    logs = db.analytics.find()

    processed = []
    for log in logs:
        processed.append({
            'user_id': log['user_id'],
            'challenge_id': log['challenge_id'],
            'event_type': log['event_type'],
            'timestamp': log['timestamp'].isoformat(),
            'hint_level': log.get('metadata', {}).get('level', ''),
            'meta_info': str(log.get('metadata', {}))
        })
    return processed
