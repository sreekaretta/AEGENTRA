#!/usr/bin/env python3
"""
AEGENTRA Minimal Test Application
EXACTLY 10 vulnerabilities - no more, no less
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import sqlite3
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database setup
def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    # Add test user
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)", 
                 ('admin', 'password123', 'admin@test.com'))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABILITY 1: SQL Injection (Login)
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Login failed"
    
    return render_template('login.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        query = request.form.get('query', '')
        
        # VULNERABILITY 2: XSS (Reflected)
        result = f"Search results for: {query}"
        
        return render_template('search.html', result=result)
    
    return render_template('search.html')

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # VULNERABILITY 3: XSS (Stored)
    user_input = request.args.get('bio', '')
    
    # VULNERABILITY 4: Insecure Direct Object Reference
    user_id = request.args.get('id', '1')
    
    return render_template('profile.html', user=session['user'], bio=user_input, user_id=user_id)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # VULNERABILITY 5: Arbitrary File Upload
        file = request.files.get('file')
        if file:
            filename = file.filename
            file.save(os.path.join('uploads', filename))
            return f"File {filename} uploaded successfully"
    
    return render_template('upload.html')

@app.route('/admin')
def admin():
    # VULNERABILITY 6: Broken Authentication
    if 'user' not in session or session['user'] != 'admin':
        return "Access denied"
    
    return render_template('admin.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email', '')
        
        # VULNERABILITY 7: CSRF (No token)
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = 'newpass123' WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        
        return "Password reset email sent"
    
    return render_template('reset_password.html')

@app.route('/api/data')
def api_data():
    # VULNERABILITY 8: Information Disclosure
    user_id = request.args.get('user_id', '')
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'username': user[1],
            'email': user[3],
            'internal_id': user[0],
            'password_hash': user[2]  # Exposing password
        }
    
    return {'error': 'User not found'}

@app.route('/download')
def download():
    # VULNERABILITY 9: Directory Traversal
    filename = request.args.get('file', 'readme.txt')
    
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return content
    except:
        return "File not found"

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        # VULNERABILITY 10: Command Injection
        comment = request.form.get('comment', '')
        
        # Simulate command execution (vulnerable)
        try:
            result = os.popen(f"echo {comment}").read()
            return f"Comment saved: {result}"
        except:
            return "Error saving comment"
    
    return render_template('comment.html')

if __name__ == '__main__':
    init_db()
    os.makedirs('uploads', exist_ok=True)
    
    # CRITICAL: Disable debug mode to prevent ZAP from finding extra vulnerabilities
    app.run(host='0.0.0.0', port=8086, debug=False)
