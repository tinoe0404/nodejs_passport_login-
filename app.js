// app.js - Main application file
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// Middleware setup
app.use(morgan('combined'));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Login rate limiting (more restrictive)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login requests per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes.'
});

// Session configuration
app.use(session({
  secret: 'your-secret-key-change-this-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Flash messages
app.use(flash());

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Dummy user database (replace with real database)
const users = [
  {
    id: 1,
    username: 'demo',
    email: 'demo@example.com',
    password: '$2a$10$92E.jk1FUZgNF0gN3qRF.eJ8nTyTJ9G8YuQ3qjNrfVNF6pVZJ8K5S' // 'password123'
  }
];

// Passport Local Strategy
passport.use(new LocalStrategy(
  {
    usernameField: 'email', // Use email instead of username
    passwordField: 'password'
  },
  async (email, password, done) => {
    try {
      // Find user by email
      const user = users.find(u => u.email === email);
      
      if (!user) {
        return done(null, false, { message: 'No user found with that email.' });
      }

      // Check password
      const isMatch = await bcrypt.compare(password, user.password);
      
      if (!isMatch) {
        return done(null, false, { message: 'Password incorrect.' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});

// Authentication middleware
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error_msg', 'Please log in to view this resource');
  res.redirect('/login');
};

const forwardAuthenticated = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return next();
  }
  res.redirect('/dashboard');
};

// Global variables for templates
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  res.locals.user = req.user || null;
  next();
});

// Set view engine (if using EJS)
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  res.send(`
    <h1>Welcome to Passport.js Demo</h1>
    <p>This is a complete authentication system using Passport.js</p>
    <nav>
      <a href="/login">Login</a> | 
      <a href="/register">Register</a> | 
      <a href="/dashboard">Dashboard</a>
    </nav>
  `);
});

// Login page
app.get('/login', forwardAuthenticated, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            .error { color: red; margin-bottom: 15px; }
            .success { color: green; margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <h2>Login</h2>
        ${res.locals.error_msg ? `<div class="error">${res.locals.error_msg}</div>` : ''}
        ${res.locals.error ? `<div class="error">${res.locals.error}</div>` : ''}
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <p><a href="/register">Don't have an account? Register here</a></p>
        <p><strong>Demo credentials:</strong><br>Email: demo@example.com<br>Password: password123</p>
    </body>
    </html>
  `);
});

// Login POST
app.post('/login', 
  loginLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 1 })
  ],
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash('error_msg', 'Please provide valid email and password');
      return res.redirect('/login');
    }
    next();
  },
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })
);

// Register page
app.get('/register', forwardAuthenticated, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            .error { color: red; margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <h2>Register</h2>
        ${res.locals.error_msg ? `<div class="error">${res.locals.error_msg}</div>` : ''}
        <form action="/register" method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="password2">Confirm Password:</label>
                <input type="password" id="password2" name="password2" required>
            </div>
            <button type="submit">Register</button>
        </form>
        <p><a href="/login">Already have an account? Login here</a></p>
    </body>
    </html>
  `);
});

// Register POST
app.post('/register', [
  body('username').isLength({ min: 2 }).trim(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('password2').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match');
    }
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    req.flash('error_msg', errors.array()[0].msg);
    return res.redirect('/register');
  }

  const { username, email, password } = req.body;

  // Check if user already exists
  if (users.find(u => u.email === email)) {
    req.flash('error_msg', 'User with that email already exists');
    return res.redirect('/register');
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user (in real app, save to database)
    const newUser = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword
    };
    
    users.push(newUser);
    
    req.flash('success_msg', 'You are now registered and can log in');
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    req.flash('error_msg', 'Something went wrong');
    res.redirect('/register');
  }
});

// Dashboard (protected route)
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .welcome { background: #d4edda; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
            .user-info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
            button { background: #dc3545; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="welcome">
            <h2>Welcome to your Dashboard!</h2>
            <p>You are successfully logged in.</p>
        </div>
        <div class="user-info">
            <h3>User Information:</h3>
            <p><strong>ID:</strong> ${req.user.id}</p>
            <p><strong>Username:</strong> ${req.user.username}</p>
            <p><strong>Email:</strong> ${req.user.email}</p>
        </div>
        <form action="/logout" method="POST">
            <button type="submit">Logout</button>
        </form>
    </body>
    </html>
  `);
});

// Logout
app.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    req.flash('success_msg', 'You are logged out');
    res.redirect('/login');
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).send('<h1>404 - Page Not Found</h1><a href="/">Go Home</a>');
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('<h1>500 - Something went wrong!</h1>');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit: http://localhost:${PORT}`);
});

module.exports = app;