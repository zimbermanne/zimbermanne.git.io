# UBAONI - Backend Migration Complete

Your website has been upgraded from local browser storage to a professional backend with a persistent SQLite database.

## What Changed

### Before (localStorage)
- All data stored only in browser memory
- Lost on browser clear or device switch
- No authentication/passwords
- No scalability

### Now (Backend + Database)
- All data persists in SQLite database (`ubaoni.db`)
- Secure password authentication with bcrypt hashing
- User registration with email and phone storage
- Posts tracked with creation timestamps and expiration
- Like system with proper user tracking
- Admin moderation system with full database access

## Database Schema

### Users Table
- `id` - Unique user ID
- `name` - Username (unique)
- `email` - Email address (unique)
- `phone` - Phone number
- `password_hash` - Bcrypt hashed password
- `created_at` - Registration timestamp

### Posts Table
- `id` - Unique post ID
- `user_id` - Reference to users table
- `message` - Post content
- `category` - Category (Announcement, Business, Greeting, Event, Other)
- `tier` - Post type (basic or featured)
- `likes` - Like count
- `created_at` - Post creation timestamp
- `expires_at` - Post expiration timestamp

### Likes Table
- `id` - Unique like ID
- `post_id` - Reference to posts table
- `user_id` - Reference to users table
- (Prevents duplicate likes)

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login with credentials

### Posts
- `GET /api/posts` - Get all active posts
- `GET /api/posts/search/:query` - Search posts
- `POST /api/posts` - Create new post
- `PUT /api/posts/:id` - Edit post
- `DELETE /api/posts/:id` - Delete post

### Likes
- `POST /api/likes/:post_id` - Toggle like
- `GET /api/likes/:post_id` - Get post likes

### Admin
- `GET /api/admin/posts` - Get all posts (admin only)

## How to Run

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Server
```bash
npm start
```
Server runs on `http://localhost:3000`

### 3. Access the Website
Open `http://localhost:3000` in your browser

### 4. Create Admin Account
Login/Register with username: `admin` and any password. This grants access to moderation features.

## Test Account
To test the system, create a user account with:
- Username: `testuser`
- Password: `password123`
- Email: `test@example.com`
- Phone: `0712345678`

## File Structure
```
zimbermanne.git.io/
├── index.html          # Login/Registration page
├── dashboard.html      # Main dashboard
├── server.js           # Express backend
├── package.json        # Dependencies
├── ubaoni.db          # SQLite database (auto-created)
└── .gitignore         # Git ignore rules
```

## Security Features

✅ **Password Hashing** - All passwords encrypted with bcrypt (10 rounds)
✅ **User Authentication** - Required for all operations
✅ **Admin Authorization** - Admin functions restricted to admin users
✅ **Post Ownership** - Users can only edit/delete their own posts
✅ **Like Prevention** - Users can't duplicate like same post

## Data Persistence

All data is automatically saved to the SQLite database:
- User registrations and credentials
- All posts with timestamps
- Like counts and user attribution
- Admin moderation history

Data persists across:
- Browser restarts
- Server restarts
- Device switches (via shared database)

## Frontend Changes

The HTML files now make API calls to the backend server instead of using localStorage:
- `index.html` - Registration and login now use `/api/register` and `/api/login`
- `dashboard.html` - All post operations use REST API endpoints

All functions work the same from a user perspective, but data is now permanently stored.

## Troubleshooting

**"Connection error. Is the server running on port 3000?"**
- Make sure `npm start` is running in another terminal
- Check that port 3000 is not in use: `lsof -i :3000`

**Database locked error**
- Stop the server and delete `ubaoni.db`, then restart
- This will recreate a fresh database

**CORS errors**
- Ensure backend server is running on localhost:3000
- Both frontend and backend must be accessible

## Next Steps

1. **Add email verification** - Send confirmation emails on registration
2. **Add image uploads** - Allow users to attach images to posts
3. **Deploy to cloud** - Move from localhost to production server
4. **Add more moderation** - Post flagging, comment system
5. **Mobile app** - React Native or Flutter frontend

Enjoy your new backend-powered UBAONI community board!
