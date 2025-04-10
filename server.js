const express = require('express');
const path = require('path');
const db = require('./database');
const session = require('express-session');
const csrf = require('csurf');
const helmet = require('helmet');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const xss = require('xss');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const logStream = fs.createWriteStream(path.join(logsDir, 'app.log'), { flags: 'a' });
function logMessage(message) {
  const timestamp = new Date().toISOString();
  logStream.write(`${timestamp} - ${message}\n`);
}

const app = express();
const port = process.env.PORT || 3000;

app.use(helmet());


app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-in-production',
  name: 'sessionId', // Don't use default name
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Prevents client-side JS from reading cookie
    secure: process.env.NODE_ENV === 'production', 
    sameSite: 'strict', 
    maxAge: 3600000 
  }
}));

// Set up CSRF protection
const csrfProtection = csrf();
app.use(csrfProtection);

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');

// Middleware to make user info and CSRF token available to templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.csrfToken = req.csrfToken();
  next();
});

app.use((req, res, next) => {
  logMessage(`${req.method} ${req.url} - ${req.ip}`);
  next();
});

app.get('/login', (req, res) => {
  res.render('login', { 
    error: req.query.error,
    message: req.query.message
  });
});

app.post('/login', [
  // Validate input
  check('username').trim().isLength({ min: 1 }).escape(),
  check('password').isLength({ min: 1 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('login', { error: 'Invalid input' });
  }

  const { username, password } = req.body;
  
  try {
    // FIXED: SQL Injection 
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (user) {
      // FIXED: Use bcrypt to securely compare passwords
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (passwordMatch) {
        req.session.user = {
          id: user.id,
          username: user.username,
          role: user.role
        };
        
        logMessage(`User logged in: ${user.username}`);
        return res.redirect('/');
      }
    }
    
    // Does not provide specific error messages
    return res.render('login', { error: 'Invalid username or password' });
  } catch (error) {
    logMessage(`Login error: ${error.message}`);
    res.render('login', { error: 'An error occurred during login' });
  }
});

app.get('/logout', (req, res) => {
  if (req.session.user) {
    logMessage(`User logged out: ${req.session.user.username}`);
  }
  
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/register', (req, res) => {
  res.render('register', { error: req.query.error });
});

app.post('/register', [
  // Validate input
  check('username').trim().isLength({ min: 3 }).escape(),
  check('email').trim().isEmail().normalizeEmail(),
  check('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('register', { error: 'Invalid input' });
  }
  
  try {
    // FIXED: Hash password before storing
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
      .run(req.body.username, hashedPassword, req.body.email, 'user');
    
    res.redirect('/login?message=Registration+successful.+Please+log+in.');
  } catch (error) {
    logMessage(`Registration error: ${error.message}`);
    res.render('register', { error: 'Username or email already exists' });
  }
});

app.get('/', (req, res) => {
  try {
    // FIXED: SQL Injection by using parameterized queries
    const searchTerm = req.query.search || '';
    let tasks = [];
    
    if (req.session.user) {
      let stmt;
      const params = [];
      
      if (req.session.user.role === 'admin') {
        stmt = db.prepare(`
          SELECT t.*, u.username 
          FROM tasks t 
          LEFT JOIN users u ON t.user_id = u.id 
          WHERE t.title LIKE ? 
          ORDER BY t.created_at DESC
        `);
        params.push('%' + searchTerm + '%');
      } else {
        stmt = db.prepare(`
          SELECT t.*, u.username 
          FROM tasks t 
          LEFT JOIN users u ON t.user_id = u.id 
          WHERE t.user_id = ? AND t.title LIKE ? 
          ORDER BY t.created_at DESC
        `);
        params.push(req.session.user.id, '%' + searchTerm + '%');
      }
      
      tasks = stmt.all(...params);
    }
    
    res.render('index', { 
      tasks, 
      searchTerm: xss(searchTerm) // FIXED: XSS by sanitizing output
    });
  } catch (error) {
    logMessage(`Error fetching tasks: ${error.message}`);
    res.status(500).render('error', { message: 'Error fetching tasks' });
  }
});

app.get('/add', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in+to+create+tasks');
  }
  
  // FIXED: XSS by sanitizing output
  const message = xss(req.query.message || '');
  res.render('add', { message });
});

app.post('/add', [
  check('title').trim().isLength({ min: 1 }).escape(),
  check('description').trim().escape()
], (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in+to+create+tasks');
  }
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('add', { error: 'Invalid input' });
  }
  
  try {
    // FIXED: Use parameterized query
    db.prepare('INSERT INTO tasks (title, description, user_id, private_notes) VALUES (?, ?, ?, ?)')
      .run(req.body.title, req.body.description || '', req.session.user.id, req.body.private_notes || '');
    
    res.redirect('/');
  } catch (error) {
    logMessage(`Error creating task: ${error.message}`);
    res.render('add', { error: 'An error occurred while creating the task' });
  }
});

// View task details
app.get('/task/:id', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in+to+view+tasks');
  }
  
  try {
    // FIXED: SQL Injection by using parameterized query
    let stmt;
    const params = [];
    
    if (req.session.user.role === 'admin') {
      stmt = db.prepare('SELECT t.*, u.username FROM tasks t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ?');
      params.push(req.params.id);
    } else {
      stmt = db.prepare('SELECT t.*, u.username FROM tasks t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ? AND t.user_id = ?');
      params.push(req.params.id, req.session.user.id);
    }
    
    const task = stmt.get(...params);
    
    if (!task) {
      return res.status(403).render('error', { message: 'Task not found or you do not have permission to view it' });
    }
    
    // FIXED: XSS by sanitizing output
    const referrer = xss(req.query.ref || '');
    res.render('task', { task, referrer });
  } catch (error) {
    logMessage(`Error fetching task: ${error.message}`);
    res.status(500).render('error', { message: 'Error fetching task' });
  }
});

// Complete task
app.post('/complete/:id', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in');
  }
  
  try {
    // FIXED: SQL Injection by using parameterized query
    if (req.session.user.role === 'admin') {
      db.prepare('UPDATE tasks SET completed = 1 WHERE id = ?').run(req.params.id);
    } else {
      db.prepare('UPDATE tasks SET completed = 1 WHERE id = ? AND user_id = ?')
        .run(req.params.id, req.session.user.id);
    }
    
    res.redirect('/');
  } catch (error) {
    logMessage(`Error completing task: ${error.message}`);
    res.status(500).render('error', { message: 'Error completing task' });
  }
});

// Delete task
app.post('/delete/:id', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in');
  }
  
  try {
    // FIXED: SQL Injection by using parameterized query
    if (req.session.user.role === 'admin') {
      db.prepare('DELETE FROM tasks WHERE id = ?').run(req.params.id);
    } else {
      db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?')
        .run(req.params.id, req.session.user.id);
    }
    
    res.redirect('/');
  } catch (error) {
    logMessage(`Error deleting task: ${error.message}`);
    res.status(500).render('error', { message: 'Error deleting task' });
  }
});

// FIXED: Secure API endpoints
app.get('/api/tasks', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    let tasks;
    
    if (req.session.user.role === 'admin') {
      tasks = db.prepare('SELECT id, title, description, created_at, completed FROM tasks').all();
    } else {
      tasks = db.prepare('SELECT id, title, description, created_at, completed FROM tasks WHERE user_id = ?')
        .all(req.session.user.id);
    }
    
    // FIXED: Only return necessary data
    res.json(tasks);
  } catch (error) {
    logMessage(`API error: ${error.message}`);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Error handlers
app.use((req, res) => {
  res.status(404).render('error', { message: 'Page not found' });
});

app.use((err, req, res, next) => {
  logMessage(`Error: ${err.message}`);
  
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', { message: 'Invalid form submission. Please try again.' });
  }
  
  res.status(500).render('error', { message: 'An unexpected error occurred' });
});

app.use((err, req, res, next) => {
  console.error('❌ Error stack trace:', err.stack);
  res.status(500).send('Something broke!');
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.warn('⚠️ CSRF token mismatch');
    res.status(403).send('Form tampered with.');
  } else {
    next(err);
  }
});


app.get('/debug-tasks', (req, res) => {
  db.all("PRAGMA table_info(tasks)", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send("DB error");
    }
    res.json(rows);
  });
});



// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});



