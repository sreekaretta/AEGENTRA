#!/usr/bin/env python3
"""
AEGENTRA Vulnerable Test Application
A deliberately vulnerable web application for testing security automation
Contains 20+ vulnerabilities across different categories
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import sqlite3
import os
import hashlib
import base64
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_for_testing'  # Weak secret key

# Database setup
DATABASE = 'database/vulnerable_app.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with sample data"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT,
            profile TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL,
            category TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product_id INTEGER,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS search_logs (
            id INTEGER PRIMARY KEY,
            query TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Insert sample users with weak passwords
        users = [
            ('admin', 'password123', 'admin@test.com', 'admin', 'Administrator account'),
            ('user1', '123456', 'user1@test.com', 'user', 'Regular user'),
            ('test', 'test', 'test@test.com', 'user', 'Test user'),
            ('guest', 'guest', 'guest@test.com', 'guest', 'Guest account')
        ]
        cursor.executemany("INSERT INTO users (username, password, email, role, profile) VALUES (?, ?, ?, ?, ?)", users)
        
        # Insert sample products
        products = [
            ('Laptop', 'High performance laptop', 999.99, 'Electronics'),
            ('Phone', 'Smartphone with latest features', 699.99, 'Electronics'),
            ('Book', 'Security testing guide', 29.99, 'Books'),
            ('Camera', 'Digital camera', 399.99, 'Electronics')
        ]
        cursor.executemany("INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)", products)
    
    conn.commit()
    conn.close()

# Routes with various vulnerabilities

@app.route('/')
def index():
    """Home page - vulnerable to XSS in comments"""
    conn = get_db()
    comments = conn.execute('SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id ORDER BY created_at DESC LIMIT 10').fetchall()
    conn.close()
    return render_template('index.html', comments=comments)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - vulnerable to SQL injection"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABILITY: SQL Injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        conn = get_db()
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page - vulnerable to weak password storage"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # VULNERABILITY: Weak password hashing
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", 
                        (username, hashed_password, email, 'user'))
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard - vulnerable to authentication bypass"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # VULNERABILITY: Information disclosure
    conn = get_db()
    users = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    products = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    
    return render_template('dashboard.html', users=users, products=products)

@app.route('/search')
def search():
    """Search page - vulnerable to SQL injection and XSS"""
    query = request.args.get('q', '')
    
    # VULNERABILITY: SQL Injection in search
    conn = get_db()
    search_query = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    products = conn.execute(search_query).fetchall()
    
    # VULNERABILITY: Log search queries without sanitization
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    conn.execute("INSERT INTO search_logs (query, ip_address, user_agent) VALUES (?, ?, ?)", 
                (query, ip_address, user_agent))
    conn.commit()
    conn.close()
    
    return render_template('search.html', query=query, products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Product detail page - vulnerable to SQL injection"""
    # VULNERABILITY: SQL Injection in product ID
    conn = get_db()
    query = f"SELECT * FROM products WHERE id = {product_id}"
    product = conn.execute(query).fetchone()
    
    comments = conn.execute('SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE product_id = ? ORDER BY created_at DESC', 
                          (product_id,)).fetchall()
    conn.close()
    
    return render_template('product.html', product=product, comments=comments)

@app.route('/comment', methods=['POST'])
def add_comment():
    """Add comment - vulnerable to XSS"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    product_id = request.form['product_id']
    comment = request.form['comment']
    
    # VULNERABILITY: Stored XSS - no sanitization
    conn = get_db()
    conn.execute("INSERT INTO comments (user_id, product_id, comment) VALUES (?, ?, ?)", 
                (session['user_id'], product_id, comment))
    conn.commit()
    conn.close()
    
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/profile')
def profile():
    """Profile page - vulnerable to IDOR"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # VULNERABILITY: Insecure Direct Object Reference
    user_id = request.args.get('id', session['user_id'])
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """File upload - vulnerable to unrestricted file upload"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # VULNERABILITY: Unrestricted file upload
            filename = file.filename
            file.save(os.path.join('uploads', filename))
            flash(f'File {filename} uploaded successfully!', 'success')
    
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files - vulnerable to path traversal"""
    # VULNERABILITY: Path traversal
    return send_from_directory('uploads', filename)

@app.route('/admin')
def admin():
    """Admin panel - vulnerable to authorization bypass"""
    # VULNERABILITY: Broken authentication - only checks session exists
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Should check for admin role but doesn't
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    logs = conn.execute("SELECT * FROM search_logs ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    
    return render_template('admin.html', users=users, logs=logs)

@app.route('/api/users')
def api_users():
    """API endpoint - vulnerable to data exposure"""
    # VULNERABILITY: No authentication required
    conn = get_db()
    users = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    
    user_list = [dict(user) for user in users]
    return jsonify(user_list)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Password reset - vulnerable to weak token generation"""
    if request.method == 'POST':
        email = request.form['email']
        
        # VULNERABILITY: Predictable reset token
        token = base64.b64encode(email.encode()).decode()
        
        flash(f'Password reset link: /reset_token?token={token}', 'info')
    
    return render_template('reset_password.html')

@app.route('/reset_token')
def reset_token():
    """Password reset token - vulnerable to token prediction"""
    token = request.args.get('token', '')
    
    # VULNERABILITY: Weak token validation
    try:
        email = base64.b64decode(token.encode()).decode()
        flash(f'Password reset for {email} - new password: password123', 'success')
    except:
        flash('Invalid token', 'error')
    
    return render_template('reset_token.html')

@app.route('/debug')
def debug():
    """Debug page - vulnerable to information disclosure"""
    # VULNERABILITY: Exposes sensitive information
    debug_info = {
        'environment': os.environ.copy(),
        'session_data': dict(session),
        'request_headers': dict(request.headers),
        'database_path': DATABASE
    }
    
    return jsonify(debug_info)

@app.route('/config')
def config():
    """Config page - vulnerable to hardcoded credentials"""
    # VULNERABILITY: Hardcoded credentials exposure
    config_data = {
        'database': {
            'type': 'sqlite',
            'path': DATABASE,
            'username': 'admin',
            'password': 'admin123'
        },
        'api_keys': {
            'google_maps': 'AIzaSyDummyKeyForTesting',
            'stripe': 'sk_test_DummyKeyForTesting'
        },
        'app_settings': {
            'debug': True,
            'secret_key': app.secret_key
        }
    }
    
    return jsonify(config_data)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8085, debug=True)