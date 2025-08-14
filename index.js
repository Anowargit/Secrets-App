require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const User = require('./models/User');
const requireAuth = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const isProd = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);

(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
    });
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
  }
})();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
  },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use((req, res, next) => {
  res.locals.year = new Date().getFullYear();
  res.locals.isAuthenticated = Boolean(req.cookies?.token);
  next();
});

app.get('/', csrfProtection, (req, res) => {
  res.render('home', { title: 'Secrets • Home', csrfToken: req.csrfToken() });
});

app.get('/register', csrfProtection, (req, res) => {
  res.render('register', { title: 'Create Account', errors: [], data: {}, csrfToken: req.csrfToken() });
});

app.post(
  '/register',
  authLimiter,
  csrfProtection,
  [
    body('name').trim().notEmpty().withMessage('Name is required').isLength({ max: 80 }).withMessage('Name is too long'),
    body('email').trim().isEmail().withMessage('Enter a valid email').normalizeEmail(),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[a-z]/).withMessage('Password must include a lowercase letter')
      .matches(/[A-Z]/).withMessage('Password must include an uppercase letter')
      .matches(/[0-9]/).withMessage('Password must include a number'),
    body('confirmPassword')
      .custom((value, { req }) => value === req.body.password).withMessage('Passwords do not match'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    const data = { name: req.body.name, email: req.body.email };
    if (!errors.isEmpty()) {
      return res.status(400).render('register', { title: 'Create Account', errors: errors.array(), data, csrfToken: req.csrfToken() });
    }
    try {
      const existing = await User.findOne({ email: req.body.email });
      if (existing) {
        return res.status(400).render('register', {
          title: 'Create Account',
          errors: [{ msg: 'Email already registered' }],
          data,
          csrfToken: req.csrfToken(),
        });
      }
      const passwordHash = await bcrypt.hash(req.body.password, 12);
      const user = await User.create({ name: req.body.name, email: req.body.email, passwordHash });
      console.log('👤 Registered:', user.email);
      // After Registration: Redirect to login page
      return res.redirect('/login');
    } catch (err) {
      console.error('Registration error:', err);
      return res.status(500).render('register', {
        title: 'Create Account',
        errors: [{ msg: 'Server error. Please try again.' }],
        data,
        csrfToken: req.csrfToken(),
      });
    }
  }
);

app.get('/login', csrfProtection, (req, res) => {
  res.render('login', { title: 'Sign In', errors: [], data: {}, csrfToken: req.csrfToken() });
});

app.post(
  '/login',
  authLimiter,
  csrfProtection,
  [
    body('email').trim().isEmail().withMessage('Enter a valid email').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    const data = { email: req.body.email };
    if (!errors.isEmpty()) {
      return res.status(400).render('login', { title: 'Sign In', errors: errors.array(), data, csrfToken: req.csrfToken() });
    }
    try {
      const user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.status(400).render('login', {
          title: 'Sign In',
          errors: [{ msg: 'Invalid email or password' }],
          data,
          csrfToken: req.csrfToken(),
        });
      }
      const match = await bcrypt.compare(req.body.password, user.passwordHash);
      if (!match) {
        return res.status(400).render('login', {
          title: 'Sign In',
          errors: [{ msg: 'Invalid email or password' }],
          data,
          csrfToken: req.csrfToken(),
        });
      }
      const token = jwt.sign(
        { sub: user._id.toString(), name: user.name, email: user.email },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.cookie('token', token, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        maxAge: 60 * 60 * 1000, 
      });
      return res.redirect('/dashboard');
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).render('login', {
        title: 'Sign In',
        errors: [{ msg: 'Server error. Please try again.' }],
        data,
        csrfToken: req.csrfToken(),
      });
    }
  }
);

app.get('/dashboard', csrfProtection, requireAuth, async (req, res) => {
  res.render('dashboard', { title: 'Your Dashboard', user: req.user, csrfToken: req.csrfToken() });
});

app.post('/logout', csrfProtection, (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'lax', secure: isProd });
  return res.redirect('/login');
});

app.use((req, res) => {
  res.status(404).render('404', { title: 'Not Found' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
