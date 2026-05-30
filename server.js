require('dotenv').config({ override: true });

const express = require('express');
const bcrypt = require('bcryptjs');   // FIX: was 'bcrypt', package is bcryptjs
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const { Pool } = require('pg');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const app = express();
const PORT = process.env.PORT || 8080;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 10;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@ubaoni.local';

// FIX: Railway sets DATABASE_URL automatically once you add a Postgres service.
// ssl is required for Railway's hosted Postgres.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.json()
    ),
    defaultMeta: { service: 'ubaoni-api' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// ── Database helpers ──────────────────────────────────────────────────────────

const readData = async () => {
    try {
        const usersRes = await pool.query(`SELECT id, name, email, phone, password_hash, created_at, role, status FROM users`);
        const postsRes = await pool.query(`SELECT id, user_id, message, category, tier, likes, created_at, expires_at FROM posts`);
        const likesRes = await pool.query(`SELECT post_id, user_id, created_at FROM likes`);

        return normalizeData({
            users: usersRes.rows.map(u => ({
                id: u.id,
                name: u.name,
                email: u.email,
                phone: u.phone,
                role: u.role || 'user',
                status: u.status || 'active',
                password_hash: u.password_hash,
                created_at: u.created_at
            })),
            posts: postsRes.rows.map(p => ({
                id: p.id,
                user_id: p.user_id,
                message: p.message,
                category: p.category,
                tier: p.tier,
                likes: p.likes || 0,
                created_at: p.created_at,
                expires_at: p.expires_at
            })),
            likes: likesRes.rows.map(l => ({
                post_id: l.post_id,
                user_id: l.user_id,
                created_at: l.created_at
            }))
        });
    } catch (error) {
        logger.error('Error reading from PostgreSQL', error);
        return normalizeData({ users: [], posts: [], likes: [] });
    }
};

const writeData = async (data) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('TRUNCATE likes, posts, users RESTART IDENTITY CASCADE');

        for (const u of data.users || []) {
            await client.query(
                `INSERT INTO users (id, name, email, phone, password_hash, role, status, created_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                [u.id || null, u.name, u.email || null, u.phone || null, u.password_hash || null,
                 u.role || 'user', u.status || 'active', u.created_at || new Date().toISOString()]
            );
        }

        for (const p of data.posts || []) {
            await client.query(
                `INSERT INTO posts (id, user_id, message, category, tier, likes, created_at, expires_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                [p.id || null, p.user_id, p.message, p.category, p.tier || 'basic',
                 p.likes || 0, p.created_at || new Date().toISOString(), p.expires_at || null]
            );
        }

        for (const l of data.likes || []) {
            await client.query(
                `INSERT INTO likes (post_id, user_id, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
                [l.post_id, l.user_id, l.created_at || new Date().toISOString()]
            );
        }

        await client.query("SELECT setval(pg_get_serial_sequence('users','id'), COALESCE((SELECT MAX(id) FROM users),1), true)");
        await client.query("SELECT setval(pg_get_serial_sequence('posts','id'), COALESCE((SELECT MAX(id) FROM posts),1), true)");

        await client.query('COMMIT');
        return true;
    } catch (error) {
        await client.query('ROLLBACK');
        logger.error('Error writing to PostgreSQL', error);
        return false;
    } finally {
        client.release();
    }
};

const normalizeData = (data) => ({
    users: (data.users || []).map(user => ({
        ...user,
        role: user.role === 'admin' ? 'admin' : 'user',
        status: user.status === 'suspended' ? 'suspended' : 'active'
    })),
    posts: data.posts || [],
    likes: data.likes || []
});

// ── Middleware ────────────────────────────────────────────────────────────────

const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login/register attempts, please try again later.',
    skipSuccessfulRequests: false
});

app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname)));
app.use((req, res, next) => { logger.info(`${req.method} ${req.path}`, { ip: req.ip }); next(); });
app.use(limiter);

// ── Validation helpers ────────────────────────────────────────────────────────

const validateString = (str, minLength = 1, maxLength = 255) => {
    if (typeof str !== 'string') return false;
    const trimmed = str.trim();
    return trimmed.length >= minLength && trimmed.length <= maxLength;
};
const validateEmail = (email) => !email || validator.isEmail(email);
const validatePhone = (phone) => !phone || (/^[\d\s+\-()]+$/.test(phone) && phone.length <= 20);
const sanitizeString = (str) => str ? validator.trim(str) : '';
const handleError = (res, error, statusCode = 500, message = 'Internal server error') => {
    logger.error(message, error);
    res.status(statusCode).json({ error: message });
};
const getNextId = (items) => items.length > 0 ? Math.max(...items.map(i => i.id || 0)) + 1 : 1;
const getPublicUser = (user) => ({ id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role || 'user', status: user.status || 'active' });
const findUserByName = (data, name) => data.users.find(u => u.name.toLowerCase() === name.toLowerCase());
const findUserById = (data, id) => data.users.find(u => u.id === id);
const findPostById = (data, id) => data.posts.find(p => p.id === id);
const isAdmin = (user) => user?.role === 'admin';
const isActive = (user) => user?.status !== 'suspended';
const withUserName = (post, users) => ({ ...post, user_name: users.find(u => u.id === post.user_id)?.name || 'Unknown' });

const requireActiveUser = (data, userId) => {
    const user = findUserById(data, userId);
    if (!user) return { error: 'User not found', statusCode: 400 };
    if (!isActive(user)) return { error: 'Account is suspended', statusCode: 403 };
    return { user };
};
const requireAdmin = (data, userId) => {
    const auth = requireActiveUser(data, userId);
    if (auth.error) return auth;
    if (!isAdmin(auth.user)) return { error: 'Admin access required', statusCode: 403 };
    return { user: auth.user };
};

// ── Schema setup ──────────────────────────────────────────────────────────────

const ensureSchema = async () => {
    try {
        // Create tables if they don't exist (idempotent)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                name          TEXT UNIQUE NOT NULL,
                email         TEXT UNIQUE,
                phone         TEXT,
                password_hash TEXT NOT NULL,
                role          TEXT DEFAULT 'user',
                status        TEXT DEFAULT 'active',
                password_reset_at TIMESTAMP,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS posts (
                id         SERIAL PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                message    TEXT NOT NULL,
                category   TEXT NOT NULL,
                tier       TEXT DEFAULT 'basic',
                likes      INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS likes (
                id      SERIAL PRIMARY KEY,
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(post_id, user_id)
            )
        `);
        // Add columns that may be missing on older databases
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'");
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'");
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_at TIMESTAMP");
        logger.info('Database schema ready');
    } catch (error) {
        logger.error('Error ensuring DB schema', error);
    }
};

const initializeAdminAccount = async () => {
    try {
        const { rows: adminRows } = await pool.query(`SELECT * FROM users WHERE role = 'admin' LIMIT 1`);
        if (adminRows.length > 0) return;

        const { rows: match } = await pool.query('SELECT * FROM users WHERE LOWER(name) = LOWER($1) LIMIT 1', [ADMIN_USERNAME]);
        if (match.length > 0) {
            await pool.query('UPDATE users SET role = $1, status = $2, email = COALESCE(email, $3) WHERE id = $4',
                ['admin', 'active', ADMIN_EMAIL, match[0].id]);
            logger.info(`Existing user promoted to admin: ${match[0].name}`);
        } else {
            const hash = bcrypt.hashSync(ADMIN_PASSWORD, BCRYPT_ROUNDS);
            await pool.query(
                'INSERT INTO users (name, email, phone, password_hash, role, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
                [ADMIN_USERNAME, ADMIN_EMAIL, null, hash, 'admin', 'active', new Date().toISOString()]
            );
            logger.info(`Seeded admin account: ${ADMIN_USERNAME}`);
        }
    } catch (error) {
        logger.error('Error initializing admin account', error);
    }
};

(async () => {
    if (!process.env.DATABASE_URL) {
        logger.error('DATABASE_URL environment variable is not set. Please add a PostgreSQL service in Railway and link it.');
        process.exit(1);
    }
    await ensureSchema();
    await initializeAdminAccount();
})();

// ── Routes ────────────────────────────────────────────────────────────────────

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        if (!validateString(name, 2, 50)) return res.status(400).json({ error: 'Name must be 2-50 characters' });
        if (!validateString(password, 6, 128)) return res.status(400).json({ error: 'Password must be 6-128 characters' });
        if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
        if (!validatePhone(phone)) return res.status(400).json({ error: 'Invalid phone format' });

        const sanitizedName = sanitizeString(name);
        const sanitizedEmail = sanitizeString(email || '');
        const sanitizedPhone = sanitizeString(phone || '');

        if (sanitizedName.toLowerCase() === ADMIN_USERNAME.toLowerCase()) {
            return res.status(403).json({ error: 'This username is reserved for the administrator account' });
        }

        const data = await readData();
        if (findUserByName(data, sanitizedName)) {
            logger.warn(`Registration failed - duplicate user: ${sanitizedName}`);
            return res.status(400).json({ error: 'Username already exists' });
        }

        const newUser = {
            id: getNextId(data.users),
            name: sanitizedName,
            email: sanitizedEmail || null,
            phone: sanitizedPhone || null,
            role: 'user',
            status: 'active',
            password_hash: await bcrypt.hash(password, BCRYPT_ROUNDS),
            created_at: new Date().toISOString()
        };
        data.users.push(newUser);
        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to save user');

        logger.info(`New user registered: ${sanitizedName}`);
        res.status(201).json(getPublicUser(newUser));
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error during registration');
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { name, password } = req.body;
        if (!validateString(name, 1, 50)) return res.status(400).json({ error: 'Invalid username' });
        if (!validateString(password, 1, 128)) return res.status(400).json({ error: 'Invalid password' });

        const sanitizedName = sanitizeString(name);
        const data = await readData();
        const user = findUserByName(data, sanitizedName);

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            logger.warn(`Login failed for user: ${sanitizedName}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        if (!isActive(user)) {
            logger.warn(`Suspended user login blocked: ${sanitizedName}`);
            return res.status(403).json({ error: 'Account is suspended' });
        }

        logger.info(`User logged in: ${sanitizedName}`);
        res.json(getPublicUser(user));
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error during login');
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const data = await readData();
        const now = new Date().toISOString();
        const posts = data.posts
            .filter(p => !p.expires_at || p.expires_at > now)
            .map(p => withUserName(p, data.users))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 1000);
        res.json(posts);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error fetching posts');
    }
});

app.get('/api/posts/search/:query', async (req, res) => {
    try {
        const query = sanitizeString(req.params.query).toLowerCase();
        if (!validateString(query, 1, 100)) return res.status(400).json({ error: 'Invalid search query' });

        const data = await readData();
        const now = new Date().toISOString();
        const posts = data.posts
            .filter(p => !p.expires_at || p.expires_at > now)
            .map(p => withUserName(p, data.users))
            .filter(p => p.message.toLowerCase().includes(query)
                      || p.user_name.toLowerCase().includes(query)
                      || p.category.toLowerCase().includes(query))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 1000);

        logger.info(`Search: ${req.params.query} (${posts.length} results)`);
        res.json(posts);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error searching posts');
    }
});

app.post('/api/posts', async (req, res) => {
    try {
        const { user_id, message, category, tier, expiration_hours } = req.body;
        if (!Number.isInteger(user_id) || user_id <= 0) return res.status(400).json({ error: 'Invalid user_id' });
        if (!validateString(message, 1, 5000)) return res.status(400).json({ error: 'Message must be 1-5000 characters' });
        if (!['Announcement', 'Business', 'Greeting', 'Event', 'Other'].includes(category)) return res.status(400).json({ error: 'Invalid category' });
        if (tier && !['basic', 'featured'].includes(tier)) return res.status(400).json({ error: 'Invalid tier' });

        const data = await readData();
        const auth = requireActiveUser(data, user_id);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const expiresAt = expiration_hours && Number(expiration_hours) > 0
            ? new Date(Date.now() + Number(expiration_hours) * 3600000).toISOString()
            : null;

        const newPost = {
            id: getNextId(data.posts),
            user_id,
            message: sanitizeString(message),
            category,
            tier: tier || 'basic',
            likes: 0,
            created_at: new Date().toISOString(),
            expires_at: expiresAt
        };
        data.posts.push(newPost);
        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to create post');

        logger.info(`Post created - ID: ${newPost.id}, User: ${user_id}`);
        res.status(201).json(newPost);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error creating post');
    }
});

app.put('/api/posts/:id', async (req, res) => {
    try {
        const { message, user_id } = req.body;
        const postId = parseInt(req.params.id, 10);
        if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: 'Invalid post_id' });
        if (!Number.isInteger(user_id) || user_id <= 0) return res.status(400).json({ error: 'Invalid user_id' });
        if (!validateString(message, 1, 5000)) return res.status(400).json({ error: 'Message must be 1-5000 characters' });

        const data = await readData();
        const post = findPostById(data, postId);
        const auth = requireActiveUser(data, user_id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });
        if (post.user_id !== user_id && !isAdmin(auth.user)) return res.status(403).json({ error: 'Unauthorized' });

        post.message = sanitizeString(message);
        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to update post');

        logger.info(`Post updated - ID: ${postId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error updating post');
    }
});

app.delete('/api/posts/:id', async (req, res) => {
    try {
        const { user_id } = req.body;
        const postId = parseInt(req.params.id, 10);
        if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: 'Invalid post_id' });
        if (!Number.isInteger(user_id) || user_id <= 0) return res.status(400).json({ error: 'Invalid user_id' });

        const data = await readData();
        const post = findPostById(data, postId);
        if (!post) return res.status(404).json({ error: 'Post not found' });

        const auth = requireActiveUser(data, user_id);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });
        if (post.user_id !== user_id && !isAdmin(auth.user)) return res.status(403).json({ error: 'Unauthorized' });

        data.posts = data.posts.filter(p => p.id !== postId);
        data.likes = data.likes.filter(l => l.post_id !== postId);
        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to delete post');

        logger.info(`Post deleted - ID: ${postId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error deleting post');
    }
});

app.post('/api/likes/:post_id', async (req, res) => {
    try {
        const { user_id } = req.body;
        const postId = parseInt(req.params.post_id, 10);
        if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: 'Invalid post_id' });
        if (!Number.isInteger(user_id) || user_id <= 0) return res.status(400).json({ error: 'Invalid user_id' });

        const data = await readData();
        const post = findPostById(data, postId);
        const auth = requireActiveUser(data, user_id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const likeIndex = data.likes.findIndex(l => l.post_id === postId && l.user_id === user_id);
        if (likeIndex >= 0) {
            data.likes.splice(likeIndex, 1);
        } else {
            data.likes.push({ post_id: postId, user_id, created_at: new Date().toISOString() });
        }
        post.likes = data.likes.filter(l => l.post_id === postId).length;
        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to update like');

        res.json({ likes: post.likes });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error toggling like');
    }
});

app.get('/api/likes/:post_id', async (req, res) => {
    try {
        const postId = parseInt(req.params.post_id, 10);
        if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: 'Invalid post_id' });

        const data = await readData();
        const likeUsers = data.likes
            .filter(l => l.post_id === postId)
            .map(l => ({ name: findUserById(data, l.user_id)?.name || 'Unknown' }));
        res.json(likeUsers);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error fetching likes');
    }
});

app.get('/api/admin/posts', async (req, res) => {
    try {
        const userId = Number(req.query.user_id);
        if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user_id' });

        const data = await readData();
        const auth = requireAdmin(data, userId);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const posts = data.posts
            .map(p => withUserName(p, data.users))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        res.json(posts);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error accessing admin posts');
    }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        const adminId = Number(req.query.user_id);
        const data = await readData();
        const auth = requireAdmin(data, adminId);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const users = data.users.map(u => ({
            ...getPublicUser(u),
            created_at: u.created_at,
            posts_count: data.posts.filter(p => p.user_id === u.id).length,
            likes_count: data.likes.filter(l => l.user_id === u.id).length
        })).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        res.json(users);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error accessing admin users');
    }
});

app.patch('/api/admin/users/:id/status', async (req, res) => {
    try {
        const adminId = Number(req.body.user_id);
        const targetId = parseInt(req.params.id, 10);
        const status = req.body.status;
        if (!['active', 'suspended'].includes(status)) return res.status(400).json({ error: 'Invalid status' });

        const data = await readData();
        const auth = requireAdmin(data, adminId);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const targetUser = findUserById(data, targetId);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });
        if (targetUser.id === auth.user.id) return res.status(400).json({ error: 'Cannot suspend own account' });
        if (targetUser.role === 'admin') return res.status(400).json({ error: 'Cannot suspend admin accounts' });

        targetUser.status = status;
        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to update user status');

        logger.info(`Admin ${adminId} changed user ${targetId} status to ${status}`);
        res.json(getPublicUser(targetUser));
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error updating user status');
    }
});

app.post('/api/admin/users/:id/reset-password', async (req, res) => {
    try {
        const adminId = Number(req.body.user_id);
        const targetId = parseInt(req.params.id, 10);
        const newPassword = req.body.password;
        if (!validateString(newPassword, 6, 128)) return res.status(400).json({ error: 'Password must be 6-128 characters' });

        const data = await readData();
        const auth = requireAdmin(data, adminId);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const targetUser = findUserById(data, targetId);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        targetUser.password_hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        targetUser.password_reset_at = new Date().toISOString();
        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to reset password');

        logger.info(`Admin ${adminId} reset password for user ${targetId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error resetting password');
    }
});

app.delete('/api/admin/users/:id', async (req, res) => {
    try {
        const adminId = Number(req.body.user_id);
        const targetId = parseInt(req.params.id, 10);
        const data = await readData();
        const auth = requireAdmin(data, adminId);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const targetUser = findUserById(data, targetId);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });
        if (targetUser.id === auth.user.id) return res.status(400).json({ error: 'Cannot delete own account' });
        if (targetUser.role === 'admin') return res.status(400).json({ error: 'Cannot delete admin accounts' });

        const targetPostIds = data.posts.filter(p => p.user_id === targetId).map(p => p.id);
        data.users = data.users.filter(u => u.id !== targetId);
        data.posts = data.posts.filter(p => p.user_id !== targetId);
        data.likes = data.likes.filter(l => l.user_id !== targetId && !targetPostIds.includes(l.post_id));
        data.posts.forEach(p => { p.likes = data.likes.filter(l => l.post_id === p.id).length; });

        if (!(await writeData(data))) return handleError(res, null, 500, 'Failed to delete user');

        logger.info(`Admin ${adminId} deleted user ${targetId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error deleting user');
    }
});

app.get('/api/admin/stats', async (req, res) => {
    try {
        const adminId = Number(req.query.user_id);
        const data = await readData();
        const auth = requireAdmin(data, adminId);
        if (auth.error) return res.status(auth.statusCode).json({ error: auth.error });

        const now = new Date().toISOString();
        const activePosts = data.posts.filter(p => !p.expires_at || p.expires_at > now);
        res.json({
            users: data.users.length,
            active_users: data.users.filter(u => u.status !== 'suspended').length,
            suspended_users: data.users.filter(u => u.status === 'suspended').length,
            admins: data.users.filter(u => u.role === 'admin').length,
            posts: data.posts.length,
            active_posts: activePosts.length,
            expired_posts: data.posts.length - activePosts.length,
            likes: data.likes.length
        });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error accessing admin stats');
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', database: 'PostgreSQL', timestamp: new Date().toISOString() });
});

app.use((req, res) => {
    logger.warn(`404 Not Found - ${req.method} ${req.path}`);
    res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

process.on('SIGINT', () => { logger.info('Server shutting down...'); process.exit(0); });

app.listen(PORT, () => {
    logger.info('========================================');
    logger.info('UBAONI Server Started');
    logger.info(`Port: ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`Database: ${process.env.DATABASE_URL ? 'PostgreSQL (connected)' : 'NOT SET'}`);
    logger.info(`http://localhost:${PORT}`);
    logger.info('========================================');
});

module.exports = app;
