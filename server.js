const express = require('express');
const path = require('path');
const db = require('./database');
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;

app.use(session({
  secret: 'insecure-secret',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false } 
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Direct string concatenation in SQL query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log('Login Query:', query);
  
  try {
    const user = db.prepare(query).get();
    
    if (user) {

      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      };
      
      return res.redirect('/');
    } else {
      return res.redirect('/login?error=Invalid+username+or+password');
    }
  } catch (error) {
    console.error('Login error:', error);
    res.redirect('/login?error=' + error.message);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login'); 
});

app.get('/register', (req, res) => {
  res.render('register', { error: req.query.error });
});

app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  try {
    //allows any input to be registered
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
      .run(username, password, email, 'user');
    
    res.redirect('/login');
  } catch (error) {
    console.error('Registration error:', error);
    res.redirect('/register?error=' + error.message);
  }
});

app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in');
  }
  
  if (req.query.message) {
    req.session.userMessage = req.query.message;
  }
  
  const searchTerm = req.query.search || '';
  let searchResults = [];
  
  if (searchTerm) {
    try {
      // SQL Injection vulnerability
      const query = `SELECT * FROM users WHERE username LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%'`;
      console.log('Search Query:', query);
      searchResults = db.prepare(query).all();
    } catch (error) {
      console.error('Search error:', error);
      searchResults = [{ error: error.message }];
    }
  }
  
  res.render('index', { 
    searchTerm,
    searchResults,
    message: req.session.userMessage || '',
    reflectedXss: req.query.reflectedXss || ''
  });
});

app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  const userId = req.session.user.id;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  
  if (!user) {
    return res.status(404).send('User not found');
  }
  
  res.render('profile', { user });
});

// API endpoint with sensitive data exposure
app.get('/api/users', (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  res.json(users);
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});