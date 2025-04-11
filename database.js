const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const winston = require('winston');

// logging for monitoring
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({ filename: 'app.log' }),
    new winston.transports.Console()
  ]
});

// Create directories
const dbDir = path.join(__dirname, 'data');
const logsDir = path.join(__dirname, 'logs');
fs.mkdirSync(dbDir, { recursive: true });
fs.mkdirSync(logsDir, { recursive: true });

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
  
  // Create table for storing logs
  db.exec(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      ip_address TEXT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count === 0) {
    // Store hashed passwords instead of plaintext
    createUser('admin', 'admin123', 'admin@example.com', 'admin');
    createUser('user1', 'password123', 'user1@example.com', 'user');
    
    logger.info('Demo users created');
  }
  
  logger.info('Database initialized');
}

// Create a user with hashed password
async function createUser(username, password, email, role) {
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
      .run(username, hashedPassword, email, role);
    return true;
  } catch (error) {
    logger.error('Error creating user:', error);
    return false;
  }
}

function logAction(userId, action, ipAddress) {
  try {
    db.prepare('INSERT INTO logs (user_id, action, ip_address) VALUES (?, ?, ?)')
      .run(userId, action, ipAddress);
  } catch (error) {
    logger.error('Error logging action:', error);
  }
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

module.exports = { db, createUser, logAction, logger };