# Backend Infrastructure Notes

## Implemented

- Local JSON file storage in `data/app-data.json`
- Express API for login, registration, posts, likes, and admin moderation
- Role-based administrator accounts
- User suspension, password reset, and account deletion tools
- bcrypt password hashing
- Input validation and sanitization
- Rate limiting for general API calls and auth endpoints
- Winston logging to console, `combined.log`, and `error.log`
- Health check at `GET /api/health`

## Local Storage Behavior

The server creates `data/app-data.json` automatically. The file stores:

- users
- posts
- likes

Login credentials are not saved as plain text. The server stores only `password_hash`.

## Start Server

```bash
npm start
```

## Health Check

```bash
GET /api/health
```

Example response:

```json
{
  "status": "OK",
  "storage": "C:\\path\\to\\project\\data\\app-data.json",
  "timestamp": "2026-05-27T10:30:00.000Z"
}
```
