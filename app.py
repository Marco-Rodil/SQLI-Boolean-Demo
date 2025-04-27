from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Create table with UNIQUE constraint on username
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT UNIQUE,
        password TEXT
    )''')
    # Insert sample users for testing (skips duplicates due to UNIQUE)
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('admin', 'secret123'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user1', 'pass456'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user2', 'qwerty789'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('marco', '05272003'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('joshua', 'Peregrin123'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('eric', '12collantes3'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('veronica', 'president'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('kyliene', 'mistica123'))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('dannieka', '123mackay'))
    conn.commit()
    conn.close()

# Fetch all users for the table (admin only)
def get_all_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username, password FROM users")
    users = c.fetchall()  # Returns list of tuples [(username, password), ...]
    conn.close()
    return users

# Vulnerable login function (prone to SQLI)
def vulnerable_login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Directly concatenating user input, such as {username} which can be used to inject SQL such as ' OR '1'='1
    query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}' ORDER BY username ASC" #<-- Remove ORDER BY for unique scenario
    c.execute(query)
    result = c.fetchone()
    conn.close()
    return result[0] if result else None  # Return username or None

# Secure login function (prevents SQLI)
def secure_login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    #Using parameterized query
    c.execute("SELECT username FROM users WHERE username = ? AND password = ?", (username, password)) #<-- Eto paramaeters
    result = c.fetchone()
    conn.close()
    return result[0] if result else None  # Return username or None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/vulnerable', methods=['POST'])
def vulnerable():
    username = request.form['username']
    password = request.form['password']
    logged_in_user = vulnerable_login(username, password)
    if logged_in_user:
        users = get_all_users()
        return render_template('users.html', logged_in_user=logged_in_user, users=users, login_type='Vulnerable')
    return "Login failed (Vulnerable)."

@app.route('/secure', methods=['POST'])
def secure():
    username = request.form['username']
    password = request.form['password']
    logged_in_user = secure_login(username, password)
    if logged_in_user:
        users = get_all_users()
        return render_template('users.html', logged_in_user=logged_in_user, users=users, login_type='Secure')
    return "Login failed (Secure)."

if __name__ == '__main__':
    init_db()
    app.run(debug=True)