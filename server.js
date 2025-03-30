const express = require('express');
const path = require('path');
const db = require('./database');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Set up EJS as the template engine
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  const tasks = db.prepare('SELECT * FROM tasks ORDER BY created_at DESC').all();
  res.render('index', { tasks });
});

app.get('/add', (req, res) => {
  res.render('add');
});

app.post('/add', (req, res) => {
  const { title, description } = req.body;
  
  db.prepare('INSERT INTO tasks (title, description) VALUES (?, ?)')
    .run(title, description || '');
    
  res.redirect('/');
});

app.post('/complete/:id', (req, res) => {
  const id = req.params.id;
  
  db.prepare('UPDATE tasks SET completed = 1 WHERE id = ?')
    .run(id);
    
  res.redirect('/');
});

app.post('/delete/:id', (req, res) => {
  const id = req.params.id;
  
  db.prepare('DELETE FROM tasks WHERE id = ?')
    .run(id);
    
  res.redirect('/');
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});