/**
 * UBAONI – Cloudflare Worker
 * Replaces server.js for production.
 * Uses D1 (SQLite-compatible) instead of node sqlite3.
 * Uses Web Crypto PBKDF2 instead of bcrypt (not available in Workers).
 */

// ── Password helpers (PBKDF2 via Web Crypto) ─────────────────────────────────

async function hashPassword(password) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 },
    keyMaterial, 256
  );
  const hex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex(salt.buffer)}:${hex(bits)}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  if (!saltHex || !hashHex) return false;
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 },
    keyMaterial, 256
  );
  const hex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex(bits) === hashHex;
}

// ── Response helpers ──────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function getBody(request) {
  try { return await request.json(); } catch { return {}; }
}

// ── Main fetch handler ────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // OPTIONS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204 });
    }

    // Only this worker handles /api/* – everything else falls through to static assets
    if (!path.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    try {
      return await route(path, method, url, request, env);
    } catch (err) {
      console.error(err);
      return json({ error: 'Internal server error' }, 500);
    }
  }
};

// ── Router ────────────────────────────────────────────────────────────────────

async function route(path, method, url, request, env) {
  const db = env.DB;

  // POST /api/register
  if (path === '/api/register' && method === 'POST') {
    const { name, email, phone, password } = await getBody(request);
    if (!name || !password) return json({ error: 'Name and password required' }, 400);
    if (password.length < 6)  return json({ error: 'Password must be at least 6 characters' }, 400);

    const hash = await hashPassword(password);
    try {
      const result = await db.prepare(
        'INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)'
      ).bind(name, email || null, phone || null, hash).run();
      return json({ id: result.meta.last_row_id, name, email, phone });
    } catch {
      return json({ error: 'Username or email already exists' }, 400);
    }
  }

  // POST /api/login
  if (path === '/api/login' && method === 'POST') {
    const { name, password } = await getBody(request);
    if (!name || !password) return json({ error: 'Name and password required' }, 400);

    const user = await db.prepare('SELECT * FROM users WHERE name = ?').bind(name).first();
    if (!user) return json({ error: 'Invalid credentials' }, 401);

    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) return json({ error: 'Invalid credentials' }, 401);

    return json({ id: user.id, name: user.name, email: user.email, phone: user.phone });
  }

  // GET /api/posts
  if (path === '/api/posts' && method === 'GET') {
    const now = new Date().toISOString();
    const { results } = await db.prepare(
      `SELECT p.*, u.name AS user_name
       FROM posts p JOIN users u ON p.user_id = u.id
       WHERE p.expires_at IS NULL OR p.expires_at > ?
       ORDER BY p.created_at DESC`
    ).bind(now).all();
    return json(results ?? []);
  }

  // POST /api/posts
  if (path === '/api/posts' && method === 'POST') {
    const { user_id, message, category, tier, expiration_hours } = await getBody(request);
    if (!user_id || !message || !category) return json({ error: 'Missing required fields' }, 400);

    const expiresAt = expiration_hours
      ? new Date(Date.now() + expiration_hours * 3_600_000).toISOString()
      : null;

    const result = await db.prepare(
      'INSERT INTO posts (user_id, message, category, tier, expires_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(user_id, message, category, tier || 'basic', expiresAt).run();

    return json({
      id: result.meta.last_row_id, user_id, message, category,
      tier: tier || 'basic', likes: 0,
      created_at: new Date().toISOString(), expires_at: expiresAt
    });
  }

  // GET /api/posts/search/:query
  const searchMatch = path.match(/^\/api\/posts\/search\/(.+)$/);
  if (searchMatch && method === 'GET') {
    const q   = `%${decodeURIComponent(searchMatch[1])}%`;
    const now = new Date().toISOString();
    const { results } = await db.prepare(
      `SELECT p.*, u.name AS user_name
       FROM posts p JOIN users u ON p.user_id = u.id
       WHERE (p.message LIKE ? OR u.name LIKE ? OR p.category LIKE ?)
         AND (p.expires_at IS NULL OR p.expires_at > ?)
       ORDER BY p.created_at DESC`
    ).bind(q, q, q, now).all();
    return json(results ?? []);
  }

  // PUT/DELETE /api/posts/:id
  const postIdMatch = path.match(/^\/api\/posts\/(\d+)$/);
  if (postIdMatch) {
    const postId = parseInt(postIdMatch[1]);

    if (method === 'PUT') {
      const { message, user_id } = await getBody(request);
      const post = await db.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
      if (!post)                  return json({ error: 'Post not found' }, 404);
      if (post.user_id !== user_id) return json({ error: 'Unauthorized' }, 403);
      await db.prepare('UPDATE posts SET message = ? WHERE id = ?').bind(message, postId).run();
      return json({ success: true });
    }

    if (method === 'DELETE') {
      const { user_id } = await getBody(request);
      const post = await db.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
      if (!post) return json({ error: 'Post not found' }, 404);

      if (post.user_id !== user_id) {
        const user = await db.prepare('SELECT name FROM users WHERE id = ?').bind(user_id).first();
        if (!user || user.name.toLowerCase() !== 'admin') return json({ error: 'Unauthorized' }, 403);
      }

      await db.batch([
        db.prepare('DELETE FROM likes WHERE post_id = ?').bind(postId),
        db.prepare('DELETE FROM posts WHERE id = ?').bind(postId)
      ]);
      return json({ success: true });
    }
  }

  // POST/GET /api/likes/:post_id
  const likeMatch = path.match(/^\/api\/likes\/(\d+)$/);
  if (likeMatch) {
    const postId = parseInt(likeMatch[1]);

    if (method === 'POST') {
      const { user_id } = await getBody(request);
      const existing = await db.prepare(
        'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
      ).bind(postId, user_id).first();

      if (existing) {
        await db.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?').bind(postId, user_id).run();
      } else {
        await db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').bind(postId, user_id).run();
      }

      const row = await db.prepare('SELECT COUNT(*) AS count FROM likes WHERE post_id = ?').bind(postId).first();
      await db.prepare('UPDATE posts SET likes = ? WHERE id = ?').bind(row.count, postId).run();
      return json({ likes: row.count });
    }

    if (method === 'GET') {
      const { results } = await db.prepare(
        'SELECT u.name FROM likes l JOIN users u ON l.user_id = u.id WHERE l.post_id = ?'
      ).bind(postId).all();
      return json(results ?? []);
    }
  }

  // GET /api/admin/posts
  if (path === '/api/admin/posts' && method === 'GET') {
    const userId = parseInt(url.searchParams.get('user_id'));
    const user   = await db.prepare('SELECT name FROM users WHERE id = ?').bind(userId).first();
    if (!user || user.name.toLowerCase() !== 'admin') return json({ error: 'Admin access required' }, 403);

    const { results } = await db.prepare(
      `SELECT p.*, u.name AS user_name
       FROM posts p JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC`
    ).all();
    return json(results ?? []);
  }

  return json({ error: 'Not found' }, 404);
}
