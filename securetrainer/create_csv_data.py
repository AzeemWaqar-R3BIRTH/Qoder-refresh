import os
import csv

# Create the data directory if it doesn't exist
os.makedirs('data', exist_ok=True)

# Define the challenges
challenges = [
    {
        'id': '1',
        'category': 'SQL Injection',
        'payload': '" or 1=1 --',
        'scenario': 'Login form that checks username and password. The application directly concatenates user input into SQL queries without proper validation.',
        'question': 'This payload was passed into a product search query. Identify the likely intention.',
        'answer': 'This payload attempts to bypass authentication by always making the WHERE clause evaluate as true.',
        'hint': 'Try to make the WHERE clause always return a valid user.',
        'difficulty': 'Beginner',
        'score_weight': '10'
    },
    {
        'id': '2',
        'category': 'SQL Injection',
        'payload': '; DROP TABLE users; --',
        'scenario': 'A search field where input is directly concatenated into SQL queries.',
        'question': 'What would this payload attempt to do if successful?',
        'answer': 'This payload attempts to execute multiple SQL statements, with the second one trying to delete the users table completely.',
        'hint': 'The semicolon is used to separate multiple SQL statements.',
        'difficulty': 'Intermediate',
        'score_weight': '20'
    },
    {
        'id': '3',
        'category': 'SQL Injection',
        'payload': "' UNION SELECT username, password FROM users --",
        'scenario': 'Product search function that displays results from a database query.',
        'question': 'How does this attack attempt to extract sensitive information?',
        'answer': 'The UNION keyword combines the results of two SELECT statements, allowing an attacker to access data from other tables.',
        'hint': 'The UNION operator can be used to append results from another query.',
        'difficulty': 'Advanced',
        'score_weight': '30'
    }
]

# Write the challenges to the CSV file
csv_path = os.path.join('data', 'final_sqli_challenges_unique.csv')
with open(csv_path, 'w', newline='', encoding='utf-8') as file:
    fieldnames = ['id', 'category', 'payload', 'scenario', 'question', 'answer', 'hint', 'difficulty', 'score_weight']
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    writer.writeheader()
    for challenge in challenges:
        writer.writerow(challenge)

print(f"Created challenges CSV file at {csv_path}")
