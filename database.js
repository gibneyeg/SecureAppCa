const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const winston = require('winston');

// Simple logger for monitoring
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({ filename: 'app.log' }),
    new winston.transports.Console()
  ]
});

const db = new Database(path.join(__dirname, 'users.db'));

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

initDb();

module.exports = { db, createUser, logAction, logger };