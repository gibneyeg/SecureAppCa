const Database = require('better-sqlite3');
const path = require('path');

// Create a new database instance and connect to it
const db = new Database(path.join(__dirname, 'tasks.db'));

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      completed INTEGER DEFAULT 0
    )
  `);
  
  console.log('Database initialized');
}

initDb();

module.exports = db;