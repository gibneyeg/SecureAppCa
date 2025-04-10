const express = require('express');
const path = require('path');
const db = require('./database');
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;

// Setup express-session (with insecure settings for demo)
app.use(session({
  secret: 'insecure-secret',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false } // No secure flag, even in production
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Set up EJS as the template engine
app.set('view engine', 'ejs');

// Middleware to make user info available to templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Login routes
app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // SQL Injection vulnerability #1: Direct string concatenation in SQL query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log('Login Query:', query);
  
  try {
    const user = db.prepare(query).get();
    
    if (user) {
      // Store user in session (but don't set httpOnly or other security flags)
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
  res.redirect('/'); 
});

// Registration route
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  try {
    // No input validation - allows any input to be registered
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
      .run(username, password, email, 'user');
    
    res.redirect('/login');
  } catch (error) {
    console.error('Registration error:', error);
    res.redirect('/register?error=' + error.message);
  }
});

app.get('/', (req, res) => {
  try {

    const searchTerm = req.query.search || '';
    let tasks = [];
    
    if (req.session.user) {
      let query;
      if (req.session.user.role === 'admin') {
        query = `SELECT t.*, u.username FROM tasks t 
                LEFT JOIN users u ON t.user_id = u.id 
                WHERE t.title LIKE '%${searchTerm}%' 
                ORDER BY t.created_at DESC`;
      } else {
        const userId = req.session.user.id;
        query = `SELECT t.*, u.username FROM tasks t 
                LEFT JOIN users u ON t.user_id = u.id 
                WHERE t.user_id = ${userId} AND t.title LIKE '%${searchTerm}%' 
                ORDER BY t.created_at DESC`;
      }
      console.log('Tasks Query:', query);
      tasks = db.prepare(query).all();
    }
    // If not logged in
    
    res.render('index', { tasks, searchTerm });
  } catch (error) {
    console.error('Error fetching tasks:', error);
    res.status(500).send('Error fetching tasks: ' + error.message);
  }
});
app.get('/add', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in+to+create+tasks');
  }
  
  // Reflected XSS vulnerability
  const message = req.query.message || '';
  res.render('add', { message });
});

app.post('/add', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in+to+create+tasks');
  }
  
  const { title, description, private_notes } = req.body;
  const userId = req.session.user.id;
  
  try {
    db.prepare('INSERT INTO tasks (title, description, user_id, private_notes) VALUES (?, ?, ?, ?)')
      .run(title, description || '', userId, private_notes || '');
    
    console.log(`Task created by user ${userId}: ${title}`);
    res.redirect('/');
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).send('Error creating task: ' + error.message);
  }
});


app.get('/task/:id', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login?error=You+must+be+logged+in+to+view+tasks');
  }
  
  try {
    const id = req.params.id;
    
    // SQL Injection vulnerability
    let query;
    if (req.session.user.role === 'admin') {
      // Admins can see all task
      query = `SELECT t.*, u.username FROM tasks t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ${id}`;
    } else {
      // Regular users can only see their own tasks
      const userId = req.session.user.id;
      query = `SELECT t.*, u.username FROM tasks t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ${id} AND t.user_id = ${userId}`;
    }
    
    console.log('Task Detail Query:', query);
    const task = db.prepare(query).get();
    
    if (!task) {
      return res.status(403).send('Task not found or you do not have permission to view it');
    }
    
    // Reflected XSS vulnerability 
    const referrer = req.query.ref || '';
    
    res.render('task', { task, referrer });
  } catch (error) {
    console.error('Error fetching task:', error);
    res.status(500).send('Error fetching task: ' + error.message);
  }
});

app.post('/complete/:id', (req, res) => {
  const id = req.params.id;
  
  try {
    if (req.session.user && req.session.user.role === 'admin') {
      // Admins can complete any task
      db.prepare('UPDATE tasks SET completed = 1 WHERE id = ?').run(id);
    } else if (req.session.user) {
      // Regular users can only complete their own tasks
      const userId = req.session.user.id;
      db.prepare('UPDATE tasks SET completed = 1 WHERE id = ? AND user_id = ?').run(id, userId);
    } else {
      db.prepare('UPDATE tasks SET completed = 1 WHERE id = ?').run(id);
    }
    
    res.redirect('/');
  } catch (error) {
    console.error('Error completing task:', error);
    res.status(500).send('Error completing task: ' + error.message);
  }
});

app.post('/delete/:id', (req, res) => {
  const id = req.params.id;
  
  try {
    if (req.session.user && req.session.user.role === 'admin') {
      // Admins can delete any task
      db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
    } else if (req.session.user) {
      // Regular users can only delete their own tasks
      const userId = req.session.user.id;
      db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(id, userId);
    } else {
      db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
    }
    
    res.redirect('/');
  } catch (error) {
    console.error('Error deleting task:', error);
    res.status(500).send('Error deleting task: ' + error.message);
  }
});

app.get('/api/tasks', (req, res) => {
  // No authentication check for API endpoint!
  const tasks = db.prepare(`
    SELECT t.*, u.username, u.email, u.password 
    FROM tasks t 
    JOIN users u ON t.user_id = u.id
  `).all();
  
  res.json(tasks);
});

// Sensitive Data Exposure 
app.get('/api/search', (req, res) => {
  try {
    const term = req.query.term || '';
    const query = `SELECT * FROM tasks WHERE title LIKE '%${term}%'`;
    const results = db.prepare(query).all();
    res.json(results);
  } catch (error) {
    // Leaking detailed error messages
    res.status(500).json({ 
      error: true, 
      message: 'Database error: ' + error.message,
      query: `SELECT * FROM tasks WHERE title LIKE '%${req.query.term}%'`
    });
  }
});

// User profile 
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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});