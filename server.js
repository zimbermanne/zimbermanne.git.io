const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// SQLite Database
const db = new sqlite3.Database(path.join(__dirname, 'ubaoni.db'), (err) => {
    if (err) console.error('Database connection error:', err);
    else console.log('Connected to SQLite database');
});

// Initialize Database Tables
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            phone TEXT,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Posts table
    db.run(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            category TEXT NOT NULL,
            tier TEXT DEFAULT 'basic',
            likes INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    // Likes table
    db.run(`
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            UNIQUE(post_id, user_id),
            FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
});

// ============ AUTH ENDPOINTS ============

// Register
app.post('/api/register', (req, res) => {
    const { name, email, phone, password } = req.body;

    if (!name || !password) {
        return res.status(400).json({ error: 'Name and password required' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Password hashing failed' });

        db.run(
            'INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)',
            [name, email, phone, hash],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Username or email already exists' });
                }
                res.json({ id: this.lastID, name, email, phone });
            }
        );
    });
});

// Login
app.post('/api/login', (req, res) => {
    const { name, password } = req.body;

    if (!name || !password) {
        return res.status(400).json({ error: 'Name and password required' });
    }

    db.get('SELECT * FROM users WHERE name = ?', [name], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        bcrypt.compare(password, user.password_hash, (err, match) => {
            if (err) return res.status(500).json({ error: 'Authentication error' });
            if (!match) return res.status(401).json({ error: 'Invalid credentials' });

            res.json({ id: user.id, name: user.name, email: user.email, phone: user.phone });
        });
    });
});

// ============ POST ENDPOINTS ============

// Create post
app.post('/api/posts', (req, res) => {
    const { user_id, message, category, tier, expiration_hours } = req.body;

    if (!user_id || !message || !category) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const expiresAt = expiration_hours 
        ? new Date(Date.now() + expiration_hours * 60 * 60 * 1000).toISOString()
        : null;

    db.run(
        'INSERT INTO posts (user_id, message, category, tier, expires_at) VALUES (?, ?, ?, ?, ?)',
        [user_id, message, category, tier || 'basic', expiresAt],
        function(err) {
            if (err) return res.status(500).json({ error: 'Failed to create post' });
            res.json({ 
                id: this.lastID, 
                user_id, 
                message, 
                category, 
                tier: tier || 'basic',
                likes: 0,
                created_at: new Date().toISOString(),
                expires_at: expiresAt
            });
        }
    );
});

// Get all posts (active only)
app.get('/api/posts', (req, res) => {
    const now = new Date().toISOString();

    db.all(
        `SELECT p.*, u.name as user_name 
         FROM posts p 
         JOIN users u ON p.user_id = u.id 
         WHERE p.expires_at IS NULL OR p.expires_at > ?
         ORDER BY p.created_at DESC`,
        [now],
        (err, posts) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(posts || []);
        }
    );
});

// Get posts by search
app.get('/api/posts/search/:query', (req, res) => {
    const query = `%${req.params.query}%`;
    const now = new Date().toISOString();

    db.all(
        `SELECT p.*, u.name as user_name 
         FROM posts p 
         JOIN users u ON p.user_id = u.id 
         WHERE (p.message LIKE ? OR u.name LIKE ? OR p.category LIKE ?)
         AND (p.expires_at IS NULL OR p.expires_at > ?)
         ORDER BY p.created_at DESC`,
        [query, query, query, now],
        (err, posts) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(posts || []);
        }
    );
});

// Update post
app.put('/api/posts/:id', (req, res) => {
    const { message, user_id } = req.body;
    const postId = req.params.id;

    // Verify ownership
    db.get('SELECT * FROM posts WHERE id = ?', [postId], (err, post) => {
        if (err || !post) return res.status(404).json({ error: 'Post not found' });
        if (post.user_id !== user_id) return res.status(403).json({ error: 'Unauthorized' });

        db.run('UPDATE posts SET message = ? WHERE id = ?', [message, postId], function(err) {
            if (err) return res.status(500).json({ error: 'Update failed' });
            res.json({ success: true });
        });
    });
});

// Delete post
app.delete('/api/posts/:id', (req, res) => {
    const { user_id } = req.body;
    const postId = req.params.id;

    // Verify ownership or admin
    db.get('SELECT * FROM posts WHERE id = ?', [postId], (err, post) => {
        if (err || !post) return res.status(404).json({ error: 'Post not found' });
        if (post.user_id !== user_id) {
            // Check if user is admin
            db.get('SELECT name FROM users WHERE id = ?', [user_id], (err, user) => {
                if (!user || user.name.toLowerCase() !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized' });
                }
                deletePostRecord(postId, res);
            });
        } else {
            deletePostRecord(postId, res);
        }
    });

    function deletePostRecord(id, response) {
        db.run('DELETE FROM likes WHERE post_id = ?', [id]);
        db.run('DELETE FROM posts WHERE id = ?', [id], function(err) {
            if (err) return response.status(500).json({ error: 'Delete failed' });
            response.json({ success: true });
        });
    }
});

// ============ LIKE ENDPOINTS ============

// Toggle like
app.post('/api/likes/:post_id', (req, res) => {
    const { user_id } = req.body;
    const postId = req.params.post_id;

    // Check if already liked
    db.get('SELECT * FROM likes WHERE post_id = ? AND user_id = ?', [postId, user_id], (err, like) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (like) {
            // Unlike
            db.run('DELETE FROM likes WHERE post_id = ? AND user_id = ?', [postId, user_id], (err) => {
                if (err) return res.status(500).json({ error: 'Unlike failed' });
                updateLikeCount(postId, res);
            });
        } else {
            // Like
            db.run('INSERT INTO likes (post_id, user_id) VALUES (?, ?)', [postId, user_id], (err) => {
                if (err) return res.status(500).json({ error: 'Like failed' });
                updateLikeCount(postId, res);
            });
        }
    });

    function updateLikeCount(id, response) {
        db.get('SELECT COUNT(*) as count FROM likes WHERE post_id = ?', [id], (err, result) => {
            if (err) return response.status(500).json({ error: 'Database error' });
            db.run('UPDATE posts SET likes = ? WHERE id = ?', [result.count, id], (err) => {
                if (err) return response.status(500).json({ error: 'Update failed' });
                response.json({ likes: result.count });
            });
        });
    }
});

// Get likes for a post
app.get('/api/likes/:post_id', (req, res) => {
    const postId = req.params.post_id;

    db.all('SELECT u.name FROM likes l JOIN users u ON l.user_id = u.id WHERE l.post_id = ?', [postId], (err, likes) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(likes || []);
    });
});

// ============ ADMIN ENDPOINTS ============

// Get all posts (admin)
app.get('/api/admin/posts', (req, res) => {
    const { user_id } = req.query;

    // Verify admin
    db.get('SELECT name FROM users WHERE id = ?', [user_id], (err, user) => {
        if (err || !user || user.name.toLowerCase() !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        db.all(
            `SELECT p.*, u.name as user_name 
             FROM posts p 
             JOIN users u ON p.user_id = u.id 
             ORDER BY p.created_at DESC`,
            (err, posts) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json(posts || []);
            }
        );
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`UBAONI server running on http://localhost:${PORT}`);
    console.log('Database: SQLite - ubaoni.db');
});
