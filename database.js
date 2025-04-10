const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'tasks.db'));

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT DEFAULT 'user'
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      completed INTEGER DEFAULT 0,
      user_id INTEGER,
      private_notes TEXT
    )
  `);
  
  // Insert demo users if none exist
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count === 0) {
    // Insecure: Storing plaintext passwords
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)').run('admin', 'admin123', 'admin@example.com', 'admin');
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)').run('user1', 'password123', 'user1@example.com', 'user');
    console.log('Demo users created');
  }
  
  console.log('Database initialized');
}

initDb();

module.exports = db;