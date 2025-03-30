const express = require('express');
const path = require('path');
const db = require('./database');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  // Get all tasks
  try {
    const tasks = db.prepare('SELECT * FROM tasks ORDER BY created_at DESC').all();
    console.log("All tasks:", tasks); // VULNERABILITY
    res.render('index', { tasks });
  } catch (error) {
    console.error('Error details:', error);
    res.status(500).send(`Server error details: ${error.message}`);
  }
});

app.get('/add', (req, res) => {
  res.render('add');
});


app.post('/add', (req, res) => {
  const { title, description } = req.body;
  
  try {
    // VULNERABILITY
    const sql = `INSERT INTO tasks (title, description) VALUES ('${title}', '${description}')`;
    
    // Execute the raw SQL query
    db.exec(sql);
    
    res.redirect('/');
  } catch (error) {
    // VULNERABILITY
    console.error("SQL Error:", error);
    res.status(500).send(`Error adding task: ${error.message}`);
  }
});

// VULNERABILITY
app.post('/complete/:id', (req, res) => {
  const taskId = req.params.id;
  
  try {
    // VULNERABILITY
    const sql = `UPDATE tasks SET completed = 1 WHERE id = ${taskId}`;
    console.log("EXECUTING SQL:", sql);
    
    db.exec(sql);
    res.redirect('/');
  } catch (error) {
    console.error('Error details:', error);
    res.status(500).send(`Error completing task: ${error.message}`);
  }
});

// VULNERABILITY
app.post('/delete/:id', (req, res) => {
  const taskId = req.params.id;
  
  try {
    // VULNERABILITY
    const sql = `DELETE FROM tasks WHERE id = ${taskId}`;
    console.log("EXECUTING SQL:", sql);
    
    db.exec(sql);
    res.redirect('/');
  } catch (error) {
    console.error('Error details:', error);
    res.status(500).send(`Error deleting task: ${error.message}`);
  }
});

// VULNERABILITY
app.get('/search', (req, res) => {
  const searchTerm = req.query.q || '';
  
  try {
    // VULNERABILITY
    const sql = `SELECT * FROM tasks WHERE title LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`;
    console.log("EXECUTING SEARCH SQL:", sql);
    
    const results = db.prepare(sql).all();
    
    // VULNERABILITY
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Search Results</title>
      </head>
      <body>
        <h1>Search Results</h1>
        
        <form action="/search" method="get">
          <input type="text" name="q" value="${searchTerm}">
          <button type="submit">Search</button>
        </form>
        
        <h2>Results for: ${searchTerm}</h2>
        <div id="resultsCount"></div>
        
        <script>
          // VULNERABILITY: DOM-based XSS
          document.getElementById('resultsCount').innerHTML = '${results.length} results found';
        </script>
        
        <ul>
          ${results.map(task => `
            <li>
              <h3>${task.title}</h3>
              <p>${task.description}</p>
              <p>Created: ${task.created_at}</p>
              
              ${task.completed 
                ? '<p>Status: Completed</p>' 
                : `
                  <p>Status: Pending</p>
                  <form method="post" action="/complete/${task.id}">
                    <button type="submit">Mark as Complete</button>
                  </form>
                `
              }
              
              <form method="post" action="/delete/${task.id}">
                <button type="submit">Delete</button>
              </form>
            </li>
          `).join('')}
        </ul>
        
        <a href="/">Back to All Tasks</a>
      </body>
      </html>
    `);
  } catch (error) {
    // VULNERABILITY
    console.error('Search error details:', error);
    res.status(500).send(`Error searching: ${error.message}`);
  }
});

// VULNERABILITY
app.post('/comment/:id', (req, res) => {
  const taskId = req.params.id;
  const comment = req.body.comment;
  
  try {

    const task = db.prepare(`SELECT * FROM tasks WHERE id = ${taskId}`).get();
    
    // Parse existing comments or create new array
    let comments = [];
    if (task.comments) {
      try {
        comments = JSON.parse(task.comments);
      } catch (e) {
        console.error('Error parsing comments:', e);
      }
    }
    
    // Add new comment
    comments.push({
      text: comment,
      timestamp: new Date().toISOString()
    });
    
    // VULNERABILITY
    const commentsJson = JSON.stringify(comments);
    const sql = `UPDATE tasks SET comments = '${commentsJson}' WHERE id = ${taskId}`;
    console.log("EXECUTING COMMENT SQL:", sql);
    
    db.exec(sql);
    
    res.redirect('/');
  } catch (error) {
    console.error('Comment error details:', error);
    res.status(500).send(`Error adding comment: ${error.message}`);
  }
});


app.use((err,  res, ) => {
  console.error('Unhandled error details:', err);
  res.status(500).send(`Server error details: ${err.stack}`);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});