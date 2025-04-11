const express = require('express');
const path = require('path');
const { db, logAction, logger } = require('./database');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 3000;

// Security headers with CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], 
      styleSrc: ["'self'"], 
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],  
      upgradeInsecureRequests: []
    }
  }
}));

// Parse cookies for CSRF
app.use(cookieParser());

app.use(session({
  secret: 'secure-random-secret-key', 
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    httpOnly: true, 
    maxAge: 3600000,
    sameSite: 'lax'
  } 
}));

const csrfProtection = csrf({ cookie: { 
  httpOnly: true,
  sameSite: 'lax'
}});

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login?error=You+must+be+logged+in');
};

app.get('/login', csrfProtection, (req, res) => {
  const error = req.query.error ? req.query.error.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
  res.render('login', { 
    error,
    csrfToken: req.csrfToken()
  });
});

app.post('/login', csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Use parameterized query instead of string concatenation
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (user) {
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (passwordMatch) {
        // Log successful login
        logAction(user.id, 'LOGIN_SUCCESS', req.ip);
        
        req.session.user = {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        };
        
        return res.redirect('/');
      }
    }
    
    // Log failed login attempt
    logAction(null, 'LOGIN_FAILED', req.ip);
    return res.redirect('/login?error=Invalid+username+or+password');
  } catch (error) {
    logger.error('Login error:', error);
    res.redirect('/login?error=' + encodeURIComponent(error.message));
  }
});

app.get('/logout', (req, res) => {
  if (req.session.user) {
    logAction(req.session.user.id, 'LOGOUT', req.ip);
  }
  req.session.destroy();
  res.redirect('/login'); 
});

app.get('/register', csrfProtection, (req, res) => {
  const error = req.query.error ? req.query.error.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
  res.render('register', { 
    error, 
    csrfToken: req.csrfToken() 
  });
});

app.post('/register', csrfProtection, async (req, res) => {
  const { username, password, email } = req.body;
  
  try {
    // Validate inputs
    if (!username || !password || !email) {
      return res.redirect('/register?error=All+fields+are+required');
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.redirect('/register?error=Username+can+only+contain+letters,+numbers,+and+underscores');
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.redirect('/register?error=Invalid+email+format');
    }
    
    const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existingUser) {
      return res.redirect('/register?error=Username+already+exists');
    }
    
    // Hash password and create user with parameterized query
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
      .run(username, hashedPassword, email, 'user');
    
    // Log successful registration
    logAction(null, 'REGISTER_SUCCESS', req.ip);
    
    res.redirect('/login?message=Registration+successful.+Please+log+in.');
  } catch (error) {
    logger.error('Registration error:', error);
    res.redirect('/register?error=' + encodeURIComponent('Registration failed. Please try again.'));
  }
});

app.get('/', isAuthenticated, csrfProtection, (req, res) => {
  // Handle safe storage of message
  if (req.query.message) {
    req.session.userMessage = req.query.message.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  
  const searchTerm = req.query.search || '';
  let searchResults = [];
  
  if (searchTerm) {
    try {
      const query = 'SELECT id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ?';
      const params = [`%${searchTerm}%`, `%${searchTerm}%`];
      
      // Log the search action
      logAction(req.session.user.id, 'SEARCH_USERS', req.ip);
      
      searchResults = db.prepare(query).all(...params);
    } catch (error) {
      logger.error('Search error:', error);
      searchResults = [];
    }
  }
  
  // Get all users for admin panel
  let allUsers = [];
  if (req.session.user && req.session.user.role === 'admin') {
    try {
      // Idont show password
      allUsers = db.prepare('SELECT id, username, email, role FROM users').all();
      
      // Log admin viewing all users
      logAction(req.session.user.id, 'VIEW_ALL_USERS', req.ip);
    } catch (error) {
      logger.error('Error fetching all users:', error);
      allUsers = [];
    }
  }
  
  res.render('index', { 
    searchTerm,
    searchResults,
    message: req.session.userMessage || '',
    reflectedXss: req.query.reflectedXss ? req.query.reflectedXss.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '',
    csrfToken: req.csrfToken(),
    allUsers: allUsers
  });
});

app.get('/profile', isAuthenticated, csrfProtection, (req, res) => {
  const userId = req.session.user.id;
  
  const user = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(userId);
  
  if (!user) {
    return res.status(404).send('User not found');
  }
  
  // Log profile access
  logAction(userId, 'VIEW_PROFILE', req.ip);
  
  res.render('profile', { 
    user,
    notification: req.query.notification ? req.query.notification.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '',
    csrfToken: req.csrfToken()
  });
});

app.use((req, res, next) => {
  res.status(404);
  res.render('404', { 
    url: req.url, 
    csrfToken: req.csrfToken ? req.csrfToken() : '' 
  });
});

// Error handler for CSRF
app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  
  logger.error('CSRF token validation failed', { ip: req.ip });
  res.status(403).send('Form tampered with');
});

app.listen(port, () => {
  logger.info(`Server running at http://localhost:${port}`);
});