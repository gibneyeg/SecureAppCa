const Database = require('better-sqlite3');
const path = require('path');

// Create a new database instance and connect to it
const db = new Database(path.join(__dirname, 'tasks.db'));

// Initialize the database with tables if they don't exist
function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      completed INTEGER DEFAULT 0,
      comments TEXT
    )
  `);
  
  console.log('Database initialized');
  
  // VULNERABILITY
  console.log('Database path:', path.join(__dirname, 'tasks.db'));
  console.log('SQLite version:', db.pragma('user_version'));
}

// VULNERABILITY
db.executeRawQuery = function(query) {
  console.log('Warning: Executing raw query:', query);
  return this.prepare(query).run();
};

initDb();

module.exports = db;