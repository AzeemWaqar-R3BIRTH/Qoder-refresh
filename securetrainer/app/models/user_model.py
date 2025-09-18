from bson import ObjectId
from flask import current_app


def get_db():
    return current_app.config['MONGO_CLIENT'].get_database()


def insert_user(user_data):
    """Insert a new user into the users collection and return their ID."""
    db = get_db()
    result = db.users.insert_one(user_data)
    return str(result.inserted_id)  # Return the inserted user ID


def get_user_by_id(user_id):
    """Get a user by ID with more robust ID handling.

    This function tries multiple approaches to find the user:
    1. First try as ObjectId
    2. Then try as string
    3. Finally try as a substring match (in case of encoding issues)
    """
    db = get_db()

    # Print debug info
    print(f"Searching for user with ID: {user_id}, type: {type(user_id)}")

    # Try as ObjectId
    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if user:
            print(f"Found user using ObjectId: {user['_id']}")
            return user
    except Exception as e:
        print(f"Error with ObjectId search: {str(e)}")

    # Try as string
    try:
        user = db.users.find_one({'_id': user_id})
        if user:
            print(f"Found user using string ID: {user['_id']}")
            return user
    except:
        pass

    # Try substring search if it might be a QR string with extra data
    if isinstance(user_id, str) and len(user_id) > 10:
        # Look for shorter patterns that might be the ID
        try:
            for possible_id in db.users.find():
                str_id = str(possible_id['_id'])
                if str_id in user_id or user_id in str_id:
                    print(f"Found user using substring match: {possible_id['_id']}")
                    return possible_id
        except:
            pass

    print(f"No user found for ID: {user_id}")
    return None


def update_user_score_level(user_id, score_delta):
    db = get_db()
    user = get_user_by_id(user_id)
    if not user:
        return

    new_score = user.get('score', 0) + score_delta
    new_level = 1 + new_score // 1000

    role_map = {
        1: "Trainee",
        2: "Junior Analyst",
        4: "Analyst",
        6: "Senior Analyst",
        8: "Lead",
        10: "Department Head"
    }

    new_role = "Trainee"
    for level, role in sorted(role_map.items()):
        if new_level >= level:
            new_role = role

    try:
        db.users.update_one(
            {'_id': user['_id']},  # Use the _id from the found user
            {'$set': {'score': new_score, 'level': new_level, 'role': new_role}}
        )
    except Exception as e:
        print(f"Error updating user score: {str(e)}")


def get_top_users(limit=5, department=None):
    db = get_db()
    query = {}
    if department:
        query['department'] = department
    users = db.users.find(query).sort('score', -1).limit(limit)

    result = []
    for u in users:
        result.append({
            'user_id': str(u['_id']),  # Include user_id in results
            'name': f"{u['first_name']} {u['last_name']}",
            'score': u.get('score', 0),
            'level': u.get('level', 1),
            'role': u.get('role', 'Trainee'),
            'department': u.get('department', 'Unknown')
        })
    return result


def get_user_rank(user_id):
    db = get_db()
    user = get_user_by_id(user_id)
    if not user:
        return {'error': 'User not found'}

    score = user.get('score', 0)
    dept = user.get('department')

    global_rank = db.users.count_documents({'score': {'$gt': score}}) + 1
    dept_rank = db.users.count_documents({'department': dept, 'score': {'$gt': score}}) + 1

    return {
        'user_id': str(user['_id']),  # Include user_id in results
        'name': f"{user['first_name']} {user['last_name']}",
        'score': score,
        'level': user.get('level', 1),
        'role': user.get('role', 'Trainee'),
        'department': dept,
        'global_rank': global_rank,
        'department_rank': dept_rank
    }


def promote_user(user_id, new_role):
    db = get_db()
    user = get_user_by_id(user_id)
    if not user:
        return False

    try:
        db.users.update_one(
            {'_id': user['_id']},  # Use the _id from the found user
            {'$set': {'role': new_role}}
        )
        return True
    except:
        return False
