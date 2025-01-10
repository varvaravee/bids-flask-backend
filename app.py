from flask import Flask, request, jsonify, session #flask is web framework to create server, request is to handle incoming requests, jsonify is to return JSON responses, session is to manage user sessions, bcrypt is to hash passwords securely
from flask_bcrypt import Bcrypt
from flask_cors import CORS #CORS to allow cross-origin requests, which is essential when frontend and backend are on different domains
import sqlite3
from datetime import timedelta
from functools import wraps

#
app = Flask(__name__) #initialize flask app 
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)
app.secret_key = '5683' # configure secret key needed for session management
bcrypt = Bcrypt(app) #handles password hashing

#set up dictionary with single user's email and hashed password for authentication purposes
#can be replaced by data in the next steps
#users = {'varvaravee@gmail.com': bcrypt.generate_password_hash('password').decode('utf-8')}

#set cookie duration
app.permanent_session_lifetime = timedelta(hours=1)

#---CREATE SQLITE TABLES---

#database setup-create new if it doesnt exist
def create_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password TEXT NOT NULL,
                   salt TEXT NOT NULL)''')
    conn.commit()
    conn.close()
#initialize database
create_db()

#create saved_passwords table
def create_saved_passwords_table():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS saved_passwords (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   user_id INTEGER NOT NULL,
                   website TEXT NOT NULL,
                   encrypted_username TEXT NOT NULL,
                   encrypted_password TEXT NOT NULL,
                   FOREIGN KEY (user_id) REFERENCES users (id))''')
    conn.commit()
    conn.close()
#initialize saved_passwords table
create_saved_passwords_table()

#decorator to ensure user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function
    

#route to handle user reg
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    salt = data['salt']

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password, salt) VALUES (?,?,?)", (username, hashed_password, salt))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 400
    finally:
        conn.close()
    
    return jsonify({"message": "User registered succesfully"}), 201

#route to handle login
@app.route('/login', methods=["POST"])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user[0], password):
        session.permanent = True #set session as permanent
        session['username'] = username
        return jsonify({"message": "Login successful", "success": True, "salt":user[1]}), 200
    else:
        return jsonify({"message": "Invalid credentials", "success": False}), 401
    
#route to handle user logout
@app.route('/logout', methods=["POST"])
@login_required
def logout():
    session.pop('username', None) #remove username from session
    return jsonify({"message": "Logged out successfully"}), 200

#route to save encrypted password
@app.route('/save_password', methods=['POST'])
@login_required
def save_password():
    data = request.get_json()
    website = data['website']
    encrypted_username = data['encrypted_username']
    encrypted_password = data['encrypted_password']

    username = session['username']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    #get user_id from username
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"message": "User not found"}), 404
    user_id = user[0]

    try:
        cursor.execute("""
                       INSERT INTO saved_passwords (user_id, website, encrypted_username, encrypted_password)
                       VALUES (?, ?, ?, ?)
                       """, (user_id, website, encrypted_username, encrypted_password))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({"message": "Failed to save password", "error": str(e)}), 500
    conn.close()

    return jsonify({"message": "Password saved successfully"}), 201

#route to retrieve all saved passwords for logged in user
@app.route('/get_passwords', methods=['GET']) 
@login_required
def get_passwords():
    username = session['username']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    #get user_id from username
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"message": "User not found"}), 404
    user_id = user[0]

    cursor.execute("""
                   SELECT website, encrypted_username, encrypted_password
                   FROM saved_passwords
                   WHERE user_id = ?
                   """, (user_id,))
    passwords = cursor.fetchall()
    conn.close()

    #format the response
    passwords_list = []
    for pwd in passwords:
        passwords_list.append({
            "website": pwd[0],
            "encrypted_username": pwd[1],
            "encrypted_password": pwd[2]
        })
    return jsonify({"passwords": passwords_list}), 200

#Route to change a saved password
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    website = data.get('website')
    new_encrypted_password = data.get('new_encrypted_password')

    if not website or not new_encrypted_password:
        return jsonify({"message": "Missing required fields"}), 400
    
    username = session['username']
   
    #connect to database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    #get user_id from the username
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"message": "User not found"}), 404
    
    user_id = user[0]

    #Update the encrypted password for the specified website
    try:
        cursor.execute("""
                       UPDATE saved_passwords
                       SET encrypted_password = ?
                       WHERE user_id = ? AND website = ?
                       """, (new_encrypted_password, user_id, website))
        
        if cursor.rowcount == 0: #check if any row was updated
            conn.close()
            return jsonify({"message": "No matching entry found"}), 404
        
        conn.commit()
        conn.close()
        return jsonify({"message": "Password updated successfully"}), 200
    
    except Exception as e:
        conn.close()
        return jsonify({"message": "Failed to update password", "error": str(e)}), 500

#delete saved password entry
@app.route('/delete_entry', methods=['DELETE'])
@login_required
def delete_entry():
    data = request.get_json()
    website = data.get('website')

    if not website:
        return jsonify({"message": "Missing required fields"}), 400

    username = session['username']

    #connect to database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    #get user_id from username
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"message": "User not found"}), 404

    user_id = user[0]

    #delete entry for specififed website
    try:
        cursor.execute("""
                        DELETE FROM saved_passwords
                        WHERE user_id = ? AND website = ?
                        """, (user_id, website))

        if cursor.rowcount == 0:  # Check if any row was deleted
            conn.close()
            return jsonify({"message": "No matching entry found"}), 404

        conn.commit()
        conn.close()
        return jsonify({"message": "Password entry deleted successfully"}), 200

    except Exception as e:
        conn.close()
        return jsonify({"message": "Failed to delete password", "error": str(e)}), 500

   
#check session status (useful to check if user still logged in
@app.route('/session', methods=['GET'])
def check_session():
    if 'username' in session:
        return jsonify({"logged_in": True, "username": session['username']}), 200
    return jsonify({"logged_in": False}), 200

#run the app
if __name__ == '__main__':
    app.run(debug=True) #runs Flask app in debug mode