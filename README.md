Deploy Link= https://secrets-app-b64t.onrender.com

# Secrets — Secure Auth Demo (Node.js + Express + EJS + MongoDB)

A small but production-grade example showing **robust authentication** patterns:

- Secure sign up with **strong password policy** and server-side validation
- **bcrypt** hashing (no plaintext passwords)
- **JWT**-based auth stored in **HttpOnly, SameSite=Lax** cookies
- **CSRF** protection on all state-changing requests
- **Helmet**, **rate limiting**, and **compression**
- Clean, modern **EJS** UI

> Purpose: an assignment-ready project to demonstrate security best practices. 🎯

---

## Features

- Register with name, email, password (8+ chars incl. lowercase, uppercase, number). Email format validated.
- After registration ⇒ **redirect to Login**.
- Show/Hide password toggle in forms.
- Login with email + password, validate formats.
- After login ⇒ **redirect to protected Dashboard** (shows user info).
- Logout ⇒ clears cookie and redirects to Login.
- JWT auth stored in **HttpOnly** cookie to block JS access; **SameSite=Lax** to reduce CSRF risk.
- Extra hardening: **Helmet**, **rate limiting**, **CSRF** tokens, and **Mongo unique index** on email.

---

## Tech Stack

- Node.js, Express, EJS
- MongoDB (Mongoose)
- bcryptjs, jsonwebtoken
- helmet, csurf, express-rate-limit, compression
- cookie-parser, express-validator

---

## Project Structure

```
secrets-app/
├── index.js
├── package.json
├── .env.example
├── models/
│   └── User.js
├── middleware/
│   └── auth.js
├── public/
│   ├── styles.css
│   └── app.js
└── views/
    ├── 404.ejs
    ├── dashboard.ejs
    ├── home.ejs
    └── register.ejs
    └── login.ejs
    └── partials/
        ├── layout-foot.ejs
        └── layout-head.ejs
```

---

## Local Setup

1. **Clone** this repo (or download the ZIP from your ChatGPT message).
2. **Install** dependencies:
   ```bash
   npm install
   ```
3. **Create `.env`** (copy `.env.example` and fill values):
   ```env
   MONGODB_URI=your_atlas_connection_string
   JWT_SECRET=a_long_random_secret_here
   NODE_ENV=development
   PORT=3000
   ```
4. **Run**:
   ```bash
   npm start
   # or during dev with autoreload
   npm run dev
   ```
5. Visit `http://localhost:3000`

> **MongoDB Atlas tip:** Create a free cluster, add a database named `secrets_db` (auto-created on first write), create a database user, and allow access from your IP or `0.0.0.0/0` during development.

---

## Security Notes

- Passwords are **hashed with bcrypt** (12 salt rounds).
- Tokens are **JWT** with 1-hour expiry.
- Auth is **stateless**; no server session storage.
- The cookie is **HttpOnly** (+ `SameSite=Lax`, `Secure` enabled in production).
- **CSRF** protection is enabled via `csurf` cookie and hidden form fields.
- **Rate limiting** protects `/login` and `/register` endpoints.

---

## Deployment — Render

1. Push code to a **GitHub** repo.
2. On [Render](https://render.com), create a **New Web Service** and connect your repo.
3. Use these settings:
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Node Version**: `18` or above (set in **Environment** > `NODE_VERSION=18` if needed)
4. **Environment Variables** (in Render dashboard):
   - `MONGODB_URI` = your Atlas connection string
   - `JWT_SECRET` = a long random string
   - `NODE_ENV` = `production`
5. Click **Deploy**. Render will provide your live URL (e.g., `https://secrets.onrender.com`).

> The process is identical to EJS/Express apps covered in the linked video.

---

## Endpoints Summary

- `GET /` – Home
- `GET /register` – Sign up form
- `POST /register` – Create account
- `GET /login` – Login form
- `POST /login` – Authenticate user
- `GET /dashboard` – **Protected** page (requires JWT cookie)
- `POST /logout` – Destroy cookie and redirect

---

## Professional README Checklist

- ✅ Project overview & features
- ✅ Tech stack
- ✅ Setup instructions
- ✅ Security details
- ✅ Deployment steps + env vars
- ✅ Screenshots (optional)
- ✅ License (MIT)

---

## License

MIT © Your Name
