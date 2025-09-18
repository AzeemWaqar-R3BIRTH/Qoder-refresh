# Generative AI recommendation system (ML-powered + fallback stub)
import os
from datetime import datetime, timedelta

# Optional numpy import
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("⚠️ Warning: numpy not available, using fallback calculations")

# Initialize model variables
model = None
label_encoder = None
model_loaded = False

def load_ml_model():
    """Load ML model and encoder with better error handling."""
    global model, label_encoder, model_loaded
    
    if model_loaded:
        return True
        
    try:
        import joblib
        MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../model")
        
        model = joblib.load(os.path.join(MODEL_PATH, "challenge_difficulty_model.pkl"))
        label_encoder = joblib.load(os.path.join(MODEL_PATH, "label_encoder.pkl"))
        model_loaded = True
        print("✅ ML model loaded successfully")
        return True
    except Exception as e:
        print(f"⚠️ Warning: Could not load ML model: {e}")
        print("🔄 Falling back to heuristic-based recommendations")
        model_loaded = False
        model = None
        label_encoder = None
        return False

def ai_recommendation_ml(user):
    """Use ML model to recommend challenge difficulty."""
    # Try to load model if not already loaded
    if not load_ml_model():
        return ai_recommendation_stub(user)
    
    try:
        # Extract features from user data
        features = extract_user_features(user)
        
        # Make prediction
        pred_encoded = model.predict([features])[0]
        difficulty_label = label_encoder.inverse_transform([pred_encoded])[0]
        
        # Map difficulty labels to standard format
        difficulty_mapping = {
            'easy': 'beginner',
            'medium': 'intermediate', 
            'hard': 'advanced',
            'expert': 'expert',
            'beginner': 'beginner',
            'intermediate': 'intermediate',
            'advanced': 'advanced'
        }
        
        return difficulty_mapping.get(difficulty_label.lower(), 'intermediate')
        
    except Exception as e:
        print(f"ML model error: {str(e)}")
        return ai_recommendation_stub(user)

def extract_user_features(user):
    """Extract numerical features from user data for ML model."""
    features = []
    
    # Basic user metrics
    features.append(user.get('level', 1))
    features.append(user.get('score', 0))
    features.append(user.get('hint_count', 0))
    features.append(user.get('challenges_completed', 0))
    
    # Performance metrics
    features.append(user.get('success_rate', 0.5))
    features.append(user.get('avg_completion_time', 300))  # seconds
    features.append(user.get('consecutive_successes', 0))
    features.append(user.get('consecutive_failures', 0))
    
    # Time-based features
    days_since_registration = (datetime.now() - user.get('registration_date', datetime.now())).days
    features.append(min(days_since_registration, 365))  # Cap at 1 year
    
    # Category-specific performance
    features.append(user.get('sql_injection_score', 0))
    features.append(user.get('xss_score', 0))
    features.append(user.get('command_injection_score', 0))
    features.append(user.get('authentication_score', 0))
    features.append(user.get('csrf_score', 0))
    
    # Normalize features to prevent extreme values
    if NUMPY_AVAILABLE:
        features = np.array(features)
        features = np.clip(features, 0, 1000)  # Clip extreme values
    else:
        # Fallback without numpy
        features = [min(max(f, 0), 1000) for f in features]
    
    return features

def ai_recommendation_stub(user):
    """Fallback: heuristic scoring based on user performance."""
    score = user.get('score', 0)
    level = user.get('level', 1)
    hint_count = user.get('hint_count', 0)
    success_rate = user.get('success_rate', 0.5)
    
    # Calculate difficulty score
    difficulty_score = 0
    
    # Base score from user level
    difficulty_score += level * 10
    
    # Adjust based on performance
    if success_rate > 0.8:
        difficulty_score += 20  # High performer
    elif success_rate < 0.4:
        difficulty_score -= 15  # Struggling user
    
    # Adjust based on hint usage
    if hint_count > 10:
        difficulty_score -= 10  # User needs more help
    elif hint_count < 3:
        difficulty_score += 15  # User is independent
    
    # Map to difficulty levels
    if difficulty_score >= 80:
        return 'expert'
    elif difficulty_score >= 60:
        return 'advanced'
    elif difficulty_score >= 40:
        return 'intermediate'
    else:
        return 'beginner'

def adaptive_difficulty_adjustment(user, challenge_result):
    """Dynamically adjust difficulty based on challenge results."""
    current_difficulty = user.get('current_difficulty', 'intermediate')
    
    # Update user performance metrics
    update_user_performance_metrics(user, challenge_result)
    
    # Calculate new difficulty recommendation
    new_difficulty = ai_recommendation_ml(user)
    
    # Smooth difficulty transitions
    difficulty_levels = ['beginner', 'intermediate', 'advanced', 'expert']
    current_index = difficulty_levels.index(current_difficulty)
    new_index = difficulty_levels.index(new_difficulty)
    
    # Only allow one level change at a time
    if abs(new_index - current_index) > 1:
        if new_index > current_index:
            new_difficulty = difficulty_levels[current_index + 1]
        else:
            new_difficulty = difficulty_levels[current_index - 1]
    
    return new_difficulty

def update_user_performance_metrics(user, challenge_result):
    """Update user performance metrics for AI learning."""
    # This would typically update the database
    # For now, we'll just print the update
    print(f"Updating performance metrics for user {user.get('_id', 'unknown')}")
    print(f"Challenge result: {challenge_result}")

def get_personalized_challenge_recommendations(user, limit=5):
    """Get personalized challenge recommendations based on user profile."""
    try:
        from app.models.challenge_model import get_user_appropriate_challenges
        return get_user_appropriate_challenges(user, limit)
    except Exception as e:
        print(f"Error getting personalized challenges: {e}")
        return []

def analyze_user_learning_patterns(user):
    """Analyze user learning patterns for AI insights."""
    patterns = {
        'strengths': [],
        'weaknesses': [],
        'learning_style': 'balanced',
        'recommended_focus': []
    }
    
    # Analyze category performance
    category_scores = {
        'sql_injection': user.get('sql_injection_score', 0),
        'xss': user.get('xss_score', 0),
        'command_injection': user.get('command_injection_score', 0),
        'authentication': user.get('authentication_score', 0),
        'csrf': user.get('csrf_score', 0)
    }
    
    # Find strengths and weaknesses
    sorted_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
    
    if sorted_categories:
        patterns['strengths'] = [cat for cat, score in sorted_categories[:2] if score > 50]
        patterns['weaknesses'] = [cat for cat, score in sorted_categories[-2:] if score < 30]
    
    # Determine learning style
    hint_usage = user.get('hint_count', 0)
    if hint_usage > 10:
        patterns['learning_style'] = 'guided'
    elif hint_usage < 3:
        patterns['learning_style'] = 'independent'
    
    # Recommend focus areas
    if patterns['weaknesses']:
        patterns['recommended_focus'] = patterns['weaknesses']
    else:
        patterns['recommended_focus'] = ['advanced_challenges', 'speed_training']
    
    return patterns

def generate_adaptive_hint(user, challenge, attempt_count):
    """Generate adaptive hints based on user performance and attempt count."""
    base_hint = challenge.get('hint', 'Think about the vulnerability type and how it can be exploited.')
    
    if attempt_count == 1:
        return base_hint
    elif attempt_count == 2:
        # More specific hint
        if challenge.get('type') == 'sql_injection':
            return f"{base_hint} Focus on SQL syntax and operators like OR, UNION, or comments."
        elif challenge.get('type') == 'xss':
            return f"{base_hint} Consider HTML tags and JavaScript event handlers."
        elif challenge.get('type') == 'command_injection':
            return f"{base_hint} Think about shell command separators and operators."
        else:
            return f"{base_hint} Look for patterns in the payload and think about the attack vector."
    else:
        # Very specific hint
        return f"Try this specific approach: {challenge.get('answer', '')[:100]}..."

def predict_user_success_probability(user, challenge):
    """Predict the probability of user successfully completing a challenge."""
    try:
        if not load_ml_model():
            return 0.5  # Default probability
        
        # Extract features
        features = extract_user_features(user)
        
        # Get challenge difficulty
        challenge_difficulty = challenge.get('difficulty', 'intermediate').lower()
        
        # Adjust features based on challenge difficulty
        difficulty_weights = {
            'beginner': 1.0,
            'intermediate': 0.8,
            'advanced': 0.6,
            'expert': 0.4
        }
        
        weight = difficulty_weights.get(challenge_difficulty, 0.7)
        
        # Simple probability calculation based on user level vs challenge difficulty
        user_level = user.get('level', 1)
        difficulty_levels = {'beginner': 1, 'intermediate': 3, 'advanced': 6, 'expert': 9}
        challenge_level = difficulty_levels.get(challenge_difficulty, 3)
        
        # Calculate success probability
        level_diff = user_level - challenge_level
        base_probability = 0.5 + (level_diff * 0.1)
        base_probability = max(0.1, min(0.9, base_probability))  # Clamp between 0.1 and 0.9
        
        # Apply weight and return
        return base_probability * weight
        
    except Exception as e:
        print(f"Error predicting success probability: {e}")
        return 0.5
