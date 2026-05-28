# Deploying UBAONI to Cloudflare

## What changed

| Before | After |
|--------|-------|
| `server.js` (Node/Express) | `worker.js` (Cloudflare Worker) |
| `sqlite3` npm package | Cloudflare D1 (managed SQLite) |
| `bcrypt` npm package | Web Crypto PBKDF2 (built-in) |
| Hardcoded `localhost:3000` | Relative `/api/...` URLs |

`server.js` is kept for **local development without Wrangler**. For production, only `worker.js` is used.

---

## First-time setup (do once)

### 1. Install Wrangler
```bash
npm install -g wrangler
wrangler login
```

### 2. Create your D1 database
```bash
wrangler d1 create ubaoni-db
```
Copy the `database_id` it prints, then paste it into `wrangler.jsonc`:
```jsonc
"database_id": "paste-your-id-here"
```

### 3. Run the schema migration
```bash
# Production database
wrangler d1 execute ubaoni-db --file=schema.sql

# Local database (for wrangler dev)
wrangler d1 execute ubaoni-db --local --file=schema.sql
```

---

## Local development (with Wrangler)

```bash
wrangler dev
```
Opens at `http://localhost:8787` — uses the local D1 database.

## Local development (with Node, old way)

```bash
npm start
```
Opens at `http://localhost:3000` — uses the local SQLite file (`ubaoni.db`).  
Note: passwords created with `server.js` (bcrypt) are **not compatible** with `worker.js` (PBKDF2). Use one or the other.

---

## Deploy to production

```bash
wrangler deploy
```

Your site will be live at `https://ubaoni.<your-subdomain>.workers.dev`

---

## Troubleshooting

**"REPLACE_WITH_YOUR_D1_DATABASE_ID" error**  
→ Run `wrangler d1 create ubaoni-db` and paste the ID into `wrangler.jsonc`.

**Login fails after switching from server.js to worker.js**  
→ Passwords are hashed differently (bcrypt vs PBKDF2). Re-register your accounts.

**"ASSETS binding not found"**  
→ Make sure `wrangler.jsonc` has `"assets": { "directory": ".", "binding": "ASSETS" }`.

**D1 errors in local dev**  
→ Make sure you ran `wrangler d1 execute ubaoni-db --local --file=schema.sql`.
