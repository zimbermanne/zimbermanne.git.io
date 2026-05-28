# UBAONI Local JSON Backend

The app now saves data to a local JSON file instead of SQLite or another database.

## Storage

Data is automatically created and saved at:

```text
data/app-data.json
```

The JSON file contains:

- `users`: registered accounts with bcrypt password hashes
- `posts`: noticeboard messages, categories, tiers, timestamps, and expiration dates
- `likes`: user/post like records

Do not commit `data/app-data.json`; it can contain private user data.

## API Endpoints

### Authentication

- `POST /api/register`
- `POST /api/login`

### Posts

- `GET /api/posts`
- `GET /api/posts/search/:query`
- `POST /api/posts`
- `PUT /api/posts/:id`
- `DELETE /api/posts/:id`

### Likes

- `POST /api/likes/:post_id`
- `GET /api/likes/:post_id`

### Admin

- `GET /api/admin/posts`

## How to Run

```bash
npm install
npm start
```

Open `http://localhost:8080` in your browser.

## Admin Account

The server seeds a protected administrator account from `.env`:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@ubaoni.local
```

Change `ADMIN_PASSWORD` before using the app with real users.

Administrator privileges:

- View all posts
- Edit any post
- Delete any post
- View all users
- Suspend and reactivate non-admin users
- Reset user passwords
- Delete non-admin users and their posts
- View system statistics

## Troubleshooting

If the app cannot read the local JSON file, stop the server and check `data/app-data.json`. If the file is corrupted, move it aside and restart the server to create a fresh file.
