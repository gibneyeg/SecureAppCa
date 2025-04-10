const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

// Create directories
const dbDir = path.join(__dirname, 'data');
const logsDir = path.join(__dirname, 'logs');
fs.mkdirSync(dbDir, { recursive: true });
fs.mkdirSync(logsDir, { recursive: true });

// Log function
function log(message) {
  const timestamp = new Date().toISOString();
  fs.appendFileSync(path.join(logsDir, 'db.log'), `${timestamp} - ${message}\n`);
  console.log(message);
}

// Create database
let db;
try {
  db = new Database(path.join(dbDir, 'tasks.db'));
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
} catch (error) {
  log(`Database error: ${error.message}`);
  process.exit(1);
}

// Initialize schema
function initSchema() {
  try {
    db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        role TEXT DEFAULT 'user'
      )
    `).run();
    
    db.prepare(`
      CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed INTEGER DEFAULT 0,
        user_id INTEGER,
        private_notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `).run();
    
    db.prepare('CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id)').run();
    
    log('Schema initialized');
  } catch (error) {
    log(`Schema error: ${error.message}`);
    throw error;
  }
}

// Create demo users separately from schema (to handle async)
function createUsers() {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count === 0) {
    try {
      // Create admin
      const adminHash = bcrypt.hashSync('admin123', 10);
      db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
        .run('admin', adminHash, 'admin@example.com', 'admin');
      
      // Create regular user
      const userHash = bcrypt.hashSync('password123', 10);
      db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
        .run('user1', userHash, 'user1@example.com', 'user');
      
      log('Demo users created');
    } catch (error) {
      log(`User creation error: ${error.message}`);
    }
  }
}

// Initialize everything
try {
  initSchema();
  createUsers();
  log('Database initialized successfully');
} catch (error) {
  log(`Initialization error: ${error.message}`);
}

module.exports = db;