"""
UBAONI Backend - Production Ready
Configured for Railway Deployment
"""

import json
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

app = Flask(__name__)
# Allow CORS from any origin for the deployment
CORS(app)

# --- Configuration ---
# Railway provides a 'PORT' env variable. We must use it.
PORT = int(os.environ.get("PORT", 3000))
DATA_DIR = Path("data")
DATA_FILE = DATA_DIR / "app-data.json"
BCRYPT_ROUNDS = int(os.getenv('BCRYPT_ROUNDS', 10))

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def init_db():
    if not DATA_DIR.exists():
        DATA_DIR.mkdir(parents=True)
    if not DATA_FILE.exists():
        with open(DATA_FILE, 'w') as f:
            json.dump({"users": [], "posts": [], "likes": []}, f)
        logger.info("Initialized new JSON data store.")

def get_data():
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {"users": [], "posts": [], "likes": []}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

init_db()

# --- Auth Routes ---

@app.post('/api/register')
def register():
    data = get_data()
    req = request.json
    name = req.get('name', '').strip()
    password = req.get('password', '')

    if any(u['name'].lower() == name.lower() for u in data['users']):
        return jsonify({'error': 'Username already exists'}), 400

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS))
    
    new_user = {
        "id": len(data['users']) + 1,
        "name": name,
        "password_hash": hashed.decode('utf-8'),
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
    
    data['users'].append(new_user)
    save_data(data)
    return jsonify({"id": new_user['id'], "name": name, "role": "user"}), 201

@app.post('/api/login')
def login():
    data = get_data()
    req = request.json
    name = req.get('name', '').strip()
    password = req.get('password', '')

    user = next((u for u in data['users'] if u['name'].lower() == name.lower()), None)
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({"id": user['id'], "name": user['name'], "role": user['role']})
    
    return jsonify({'error': 'Invalid credentials'}), 401

# --- Post Routes ---

@app.get('/api/posts')
def get_posts():
    data = get_data()
    now = datetime.now()
    active_posts = [p for p in data['posts'] if not p.get('expires_at') or datetime.fromisoformat(p['expires_at']) > now]
    active_posts.sort(key=lambda x: (x['tier'] != 'featured', x['created_at']), reverse=True)
    return jsonify(active_posts)

@app.get('/api/posts/search/<query>')
def search_posts(query):
    data = get_data()
    query = query.lower()
    now = datetime.now()
    results = [p for p in data['posts'] if (query in p['message'].lower() or query in p['category'].lower() or query in p['user_name'].lower()) and (not p.get('expires_at') or datetime.fromisoformat(p['expires_at']) > now)]
    results.sort(key=lambda x: (x['tier'] != 'featured', x['created_at']), reverse=True)
    return jsonify(results)

@app.post('/api/posts')
def create_post():
    data = get_data()
    req = request.json
    user_id = req.get('user_id')
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user: return jsonify({'error': 'User not found'}), 404

    now = datetime.now()
    expires = now + timedelta(hours=req.get('expiration_hours', 24))

    new_post = {
        "id": len(data['posts']) + 1,
        "user_id": user_id,
        "user_name": user['name'],
        "message": req.get('message'),
        "category": req.get('category'),
        "tier": req.get('tier', 'basic'),
        "likes": 0,
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat()
    }
    
    data['posts'].append(new_post)
    save_data(data)
    return jsonify(new_post), 201

@app.delete('/api/posts/<int:post_id>')
def delete_post(post_id):
    data = get_data()
    user_id = request.json.get('user_id')
    post_idx = next((i for i, p in enumerate(data['posts']) if p['id'] == post_id), None)
    
    if post_idx is not None:
        user = next((u for u in data['users'] if u['id'] == user_id), None)
        if data['posts'][post_idx]['user_id'] == user_id or (user and user['role'] == 'admin'):
            data['posts'].pop(post_idx)
            save_data(data)
            return jsonify({'success': True})
    return jsonify({'error': 'Unauthorized or not found'}), 403

# --- Health Check ---
@app.get('/')
def home():
    return "UBAONI Backend is Live!"

if __name__ == '__main__':
    # CRITICAL FOR RAILWAY: Bind to 0.0.0.0 and dynamic PORT
    logger.info(f"Starting server on port {PORT}")
    app.run(host='0.0.0.0', port=PORT)
