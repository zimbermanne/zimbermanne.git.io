require('dotenv').config({ override: true });

const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const app = express();
const PORT = process.env.PORT || 8080;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 10;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@ubaoni.local';

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'app-data.json');
const DEFAULT_DATA = {
    users: [],
    posts: [],
    likes: []
};

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

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

const readData = () => {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            writeData(DEFAULT_DATA);
            return structuredClone(DEFAULT_DATA);
        }

        const raw = fs.readFileSync(DATA_FILE, 'utf-8');
        const parsed = JSON.parse(raw);

        return normalizeData(parsed);
    } catch (error) {
        logger.error(`Error reading local JSON data file: ${DATA_FILE}`, error);
        return structuredClone(DEFAULT_DATA);
    }
};

const writeData = (data) => {
    try {
        const normalizedData = normalizeData(data);

        fs.writeFileSync(DATA_FILE, JSON.stringify(normalizedData, null, 2), 'utf-8');
        return true;
    } catch (error) {
        logger.error(`Error writing local JSON data file: ${DATA_FILE}`, error);
        return false;
    }
};

const normalizeData = (data) => {
    const users = Array.isArray(data.users) ? data.users : [];
    const posts = Array.isArray(data.posts) ? data.posts : [];
    const likes = Array.isArray(data.likes) ? data.likes : [];

    return {
        users: users.map(user => ({
            ...user,
            role: user.role === 'admin' ? 'admin' : 'user',
            status: user.status === 'suspended' ? 'suspended' : 'active'
        })),
        posts,
        likes
    };
};

writeData(readData());

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

app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`, { ip: req.ip });
    next();
});

app.use(limiter);

const validateString = (str, minLength = 1, maxLength = 255) => {
    if (typeof str !== 'string') return false;
    const trimmed = str.trim();
    return trimmed.length >= minLength && trimmed.length <= maxLength;
};

const validateEmail = (email) => {
    if (!email) return true;
    return validator.isEmail(email);
};

const validatePhone = (phone) => {
    if (!phone) return true;
    return /^[\d\s+\-()]+$/.test(phone) && phone.length <= 20;
};

const sanitizeString = (str) => {
    if (!str) return '';
    return validator.trim(str);
};

const handleError = (res, error, statusCode = 500, message = 'Internal server error') => {
    logger.error(message, error);
    res.status(statusCode).json({ error: message });
};

const getNextId = (items) => {
    return items.length > 0 ? Math.max(...items.map(item => item.id || 0)) + 1 : 1;
};

const getPublicUser = (user) => ({
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role || 'user',
    status: user.status || 'active'
});

const findUserByName = (data, name) => {
    return data.users.find(user => user.name.toLowerCase() === name.toLowerCase());
};

const findUserById = (data, id) => {
    return data.users.find(user => user.id === id);
};

const findPostById = (data, id) => {
    return data.posts.find(post => post.id === id);
};

const isAdmin = (user) => {
    return user?.role === 'admin';
};

const isActive = (user) => {
    return user?.status !== 'suspended';
};

const requireActiveUser = (data, userId) => {
    const user = findUserById(data, userId);
    if (!user) {
        return { error: 'User not found', statusCode: 400 };
    }
    if (!isActive(user)) {
        return { error: 'Account is suspended', statusCode: 403 };
    }
    return { user };
};

const requireAdmin = (data, userId) => {
    const auth = requireActiveUser(data, userId);
    if (auth.error) return auth;
    if (!isAdmin(auth.user)) {
        return { error: 'Admin access required', statusCode: 403 };
    }
    return { user: auth.user };
};

const withUserName = (post, users) => ({
    ...post,
    user_name: users.find(user => user.id === post.user_id)?.name || 'Unknown'
});

const initializeAdminAccount = () => {
    const data = readData();
    const existingAdmin = data.users.find(user => user.role === 'admin');

    if (existingAdmin) {
        return;
    }

    const matchingUser = findUserByName(data, ADMIN_USERNAME);
    if (matchingUser) {
        matchingUser.role = 'admin';
        matchingUser.status = 'active';
        matchingUser.email = matchingUser.email || ADMIN_EMAIL;
        logger.info(`Existing user promoted to admin: ${matchingUser.name}`);
    } else {
        data.users.push({
            id: getNextId(data.users),
            name: ADMIN_USERNAME,
            email: ADMIN_EMAIL,
            phone: null,
            role: 'admin',
            status: 'active',
            password_hash: bcrypt.hashSync(ADMIN_PASSWORD, BCRYPT_ROUNDS),
            created_at: new Date().toISOString()
        });
        logger.info(`Seeded admin account: ${ADMIN_USERNAME}`);
    }

    writeData(data);
};

initializeAdminAccount();

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        if (!validateString(name, 2, 50)) {
            return res.status(400).json({ error: 'Name must be 2-50 characters' });
        }
        if (!validateString(password, 6, 128)) {
            return res.status(400).json({ error: 'Password must be 6-128 characters' });
        }
        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Invalid phone format' });
        }

        const sanitizedName = sanitizeString(name);
        const sanitizedEmail = sanitizeString(email || '');
        const sanitizedPhone = sanitizeString(phone || '');
        const data = readData();

        if (sanitizedName.toLowerCase() === ADMIN_USERNAME.toLowerCase()) {
            return res.status(403).json({ error: 'This username is reserved for the administrator account' });
        }

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

        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to save user locally');
        }

        logger.info(`New user registered locally: ${sanitizedName}`);
        res.status(201).json(getPublicUser(newUser));
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error during registration');
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { name, password } = req.body;

        if (!validateString(name, 1, 50)) {
            return res.status(400).json({ error: 'Invalid username' });
        }
        if (!validateString(password, 1, 128)) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        const sanitizedName = sanitizeString(name);
        const data = readData();
        const user = findUserByName(data, sanitizedName);

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            logger.warn(`Login failed for user: ${sanitizedName}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        if (!isActive(user)) {
            logger.warn(`Suspended user login blocked: ${sanitizedName}`);
            return res.status(403).json({ error: 'Account is suspended' });
        }

        logger.info(`User logged in locally: ${sanitizedName}`);
        res.json(getPublicUser(user));
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error during login');
    }
});

app.post('/api/posts', (req, res) => {
    try {
        const { user_id, message, category, tier, expiration_hours } = req.body;

        if (!Number.isInteger(user_id) || user_id <= 0) {
            return res.status(400).json({ error: 'Invalid user_id' });
        }
        if (!validateString(message, 1, 5000)) {
            return res.status(400).json({ error: 'Message must be 1-5000 characters' });
        }
        if (!['Announcement', 'Business', 'Greeting', 'Event', 'Other'].includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        if (tier && !['basic', 'featured'].includes(tier)) {
            return res.status(400).json({ error: 'Invalid tier' });
        }

        const data = readData();
        const auth = requireActiveUser(data, user_id);
        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const expiresAt = expiration_hours && Number(expiration_hours) > 0
            ? new Date(Date.now() + Number(expiration_hours) * 60 * 60 * 1000).toISOString()
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

        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to create post locally');
        }

        logger.info(`Post created locally - ID: ${newPost.id}, User: ${user_id}`);
        res.status(201).json(newPost);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error creating post');
    }
});

app.get('/api/posts', (req, res) => {
    try {
        const data = readData();
        const now = new Date().toISOString();

        const posts = data.posts
            .filter(post => !post.expires_at || post.expires_at > now)
            .map(post => withUserName(post, data.users))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 1000);

        res.json(posts);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error fetching posts');
    }
});

app.get('/api/posts/search/:query', (req, res) => {
    try {
        const query = sanitizeString(req.params.query).toLowerCase();
        if (!validateString(query, 1, 100)) {
            return res.status(400).json({ error: 'Invalid search query' });
        }

        const data = readData();
        const now = new Date().toISOString();
        const posts = data.posts
            .filter(post => !post.expires_at || post.expires_at > now)
            .map(post => withUserName(post, data.users))
            .filter(post => {
                return post.message.toLowerCase().includes(query)
                    || post.user_name.toLowerCase().includes(query)
                    || post.category.toLowerCase().includes(query);
            })
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 1000);

        logger.info(`Search executed locally: ${req.params.query} (${posts.length} results)`);
        res.json(posts);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error searching posts');
    }
});

app.put('/api/posts/:id', (req, res) => {
    try {
        const { message, user_id } = req.body;
        const postId = parseInt(req.params.id, 10);

        if (!Number.isInteger(postId) || postId <= 0) {
            return res.status(400).json({ error: 'Invalid post_id' });
        }
        if (!Number.isInteger(user_id) || user_id <= 0) {
            return res.status(400).json({ error: 'Invalid user_id' });
        }
        if (!validateString(message, 1, 5000)) {
            return res.status(400).json({ error: 'Message must be 1-5000 characters' });
        }

        const data = readData();
        const post = findPostById(data, postId);
        const auth = requireActiveUser(data, user_id);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }
        if (post.user_id !== user_id && !isAdmin(auth.user)) {
            logger.warn(`Unauthorized update attempt - Post: ${postId}, User: ${user_id}`);
            return res.status(403).json({ error: 'Unauthorized' });
        }

        post.message = sanitizeString(message);

        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to update post locally');
        }

        logger.info(`Post updated locally - ID: ${postId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error updating post');
    }
});

app.delete('/api/posts/:id', (req, res) => {
    try {
        const { user_id } = req.body;
        const postId = parseInt(req.params.id, 10);

        if (!Number.isInteger(postId) || postId <= 0) {
            return res.status(400).json({ error: 'Invalid post_id' });
        }
        if (!Number.isInteger(user_id) || user_id <= 0) {
            return res.status(400).json({ error: 'Invalid user_id' });
        }

        const data = readData();
        const post = findPostById(data, postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const auth = requireActiveUser(data, user_id);
        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        if (post.user_id !== user_id && !isAdmin(auth.user)) {
            logger.warn(`Unauthorized delete attempt - Post: ${postId}, User: ${user_id}`);
            return res.status(403).json({ error: 'Unauthorized' });
        }

        data.posts = data.posts.filter(item => item.id !== postId);
        data.likes = data.likes.filter(like => like.post_id !== postId);

        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to delete post locally');
        }

        logger.info(`Post deleted locally - ID: ${postId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error deleting post');
    }
});

app.post('/api/likes/:post_id', (req, res) => {
    try {
        const { user_id } = req.body;
        const postId = parseInt(req.params.post_id, 10);

        if (!Number.isInteger(postId) || postId <= 0) {
            return res.status(400).json({ error: 'Invalid post_id' });
        }
        if (!Number.isInteger(user_id) || user_id <= 0) {
            return res.status(400).json({ error: 'Invalid user_id' });
        }

        const data = readData();
        const post = findPostById(data, postId);
        const auth = requireActiveUser(data, user_id);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const likeIndex = data.likes.findIndex(like => like.post_id === postId && like.user_id === user_id);

        if (likeIndex >= 0) {
            data.likes.splice(likeIndex, 1);
        } else {
            data.likes.push({
                post_id: postId,
                user_id,
                created_at: new Date().toISOString()
            });
        }

        post.likes = data.likes.filter(like => like.post_id === postId).length;

        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to update like locally');
        }

        logger.info(`Post like toggled locally - ID: ${postId}, User: ${user_id}`);
        res.json({ likes: post.likes });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error toggling like');
    }
});

app.get('/api/likes/:post_id', (req, res) => {
    try {
        const postId = parseInt(req.params.post_id, 10);

        if (!Number.isInteger(postId) || postId <= 0) {
            return res.status(400).json({ error: 'Invalid post_id' });
        }

        const data = readData();
        const likeUsers = data.likes
            .filter(like => like.post_id === postId)
            .map(like => {
                const user = findUserById(data, like.user_id);
                return { name: user?.name || 'Unknown' };
            });

        res.json(likeUsers);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error fetching likes');
    }
});

app.get('/api/admin/posts', (req, res) => {
    try {
        const userId = Number(req.query.user_id);

        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: 'Invalid user_id' });
        }

        const data = readData();
        const auth = requireAdmin(data, userId);
        if (auth.error) {
            logger.warn(`Unauthorized admin access attempt - User: ${userId}`);
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const posts = data.posts
            .map(post => withUserName(post, data.users))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        logger.info(`Admin accessed local posts - ${posts.length} posts`);
        res.json(posts);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error accessing admin posts');
    }
});

app.get('/api/admin/users', (req, res) => {
    try {
        const adminId = Number(req.query.user_id);
        const data = readData();
        const auth = requireAdmin(data, adminId);

        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const users = data.users
            .map(user => ({
                ...getPublicUser(user),
                created_at: user.created_at,
                posts_count: data.posts.filter(post => post.user_id === user.id).length,
                likes_count: data.likes.filter(like => like.user_id === user.id).length
            }))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json(users);
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error accessing admin users');
    }
});

app.patch('/api/admin/users/:id/status', (req, res) => {
    try {
        const adminId = Number(req.body.user_id);
        const targetId = parseInt(req.params.id, 10);
        const status = req.body.status;

        if (!['active', 'suspended'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const data = readData();
        const auth = requireAdmin(data, adminId);
        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const targetUser = findUserById(data, targetId);
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (targetUser.id === auth.user.id) {
            return res.status(400).json({ error: 'Administrator cannot suspend own account' });
        }
        if (targetUser.role === 'admin' && status === 'suspended') {
            return res.status(400).json({ error: 'Administrator accounts cannot be suspended here' });
        }

        targetUser.status = status;
        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to update user status');
        }

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

        if (!validateString(newPassword, 6, 128)) {
            return res.status(400).json({ error: 'Password must be 6-128 characters' });
        }

        const data = readData();
        const auth = requireAdmin(data, adminId);
        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const targetUser = findUserById(data, targetId);
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        targetUser.password_hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        targetUser.password_reset_at = new Date().toISOString();

        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to reset password');
        }

        logger.info(`Admin ${adminId} reset password for user ${targetId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error resetting password');
    }
});

app.delete('/api/admin/users/:id', (req, res) => {
    try {
        const adminId = Number(req.body.user_id);
        const targetId = parseInt(req.params.id, 10);
        const data = readData();
        const auth = requireAdmin(data, adminId);

        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const targetUser = findUserById(data, targetId);
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (targetUser.id === auth.user.id) {
            return res.status(400).json({ error: 'Administrator cannot delete own account' });
        }
        if (targetUser.role === 'admin') {
            return res.status(400).json({ error: 'Administrator accounts cannot be deleted here' });
        }

        const targetPostIds = data.posts
            .filter(post => post.user_id === targetId)
            .map(post => post.id);

        data.users = data.users.filter(user => user.id !== targetId);
        data.posts = data.posts.filter(post => post.user_id !== targetId);
        data.likes = data.likes.filter(like => like.user_id !== targetId && !targetPostIds.includes(like.post_id));

        data.posts.forEach(post => {
            post.likes = data.likes.filter(like => like.post_id === post.id).length;
        });

        if (!writeData(data)) {
            return handleError(res, null, 500, 'Failed to delete user');
        }

        logger.info(`Admin ${adminId} deleted user ${targetId}`);
        res.json({ success: true });
    } catch (error) {
        handleError(res, error, 500, 'Unexpected error deleting user');
    }
});

app.get('/api/admin/stats', (req, res) => {
    try {
        const adminId = Number(req.query.user_id);
        const data = readData();
        const auth = requireAdmin(data, adminId);

        if (auth.error) {
            return res.status(auth.statusCode).json({ error: auth.error });
        }

        const now = new Date().toISOString();
        const activePosts = data.posts.filter(post => !post.expires_at || post.expires_at > now);

        res.json({
            users: data.users.length,
            active_users: data.users.filter(user => user.status !== 'suspended').length,
            suspended_users: data.users.filter(user => user.status === 'suspended').length,
            admins: data.users.filter(user => user.role === 'admin').length,
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
    res.json({
        status: 'OK',
        storage: DATA_FILE,
        timestamp: new Date().toISOString()
    });
});

app.use((req, res) => {
    logger.warn(`404 Not Found - ${req.method} ${req.path}`);
    res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

process.on('SIGINT', () => {
    logger.info('Server shutting down...');
    process.exit(0);
});

app.listen(PORT, () => {
    logger.info('========================================');
    logger.info('UBAONI Server Started');
    logger.info(`Port: ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`Local JSON storage: ${DATA_FILE}`);
    logger.info(`http://localhost:${PORT}`);
    logger.info('========================================');
});

module.exports = app;
