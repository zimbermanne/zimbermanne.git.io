# UBAONI

Tanzania public noticeboard project.

## How to Run

1. Install dependencies with `npm install`.
2. Start the local server with `npm start`.
3. Open `http://localhost:8080` in your browser.
4. Register or login.
5. Start posting.

All user accounts, posts, and likes are saved locally in `data/app-data.json`. Passwords are stored as bcrypt hashes, not plain text.

## How to Use

### Posting

- Choose a category.
- Write your message.
- Click `Post Free` or `Post Featured (TZS 5,000)`.

### Featured Posts

- Simulated M-Pesa payment flow.
- Posts expire based on the selected expiration time.

### Admin Access

- Login with the seeded administrator account from `.env`.
- Default local credentials are `admin` / `admin123`.
- Click the admin button in the dashboard.
- Admin can moderate posts, manage users, suspend accounts, reset passwords, and view statistics.

## License

This project is for educational and demonstration purposes.
