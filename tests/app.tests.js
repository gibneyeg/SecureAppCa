const { test, expect } = require('@playwright/test');

const BASE_URL = 'http://localhost:3000';
const ADMIN_USER = { username: 'admin', password: 'admin123' };
const REGULAR_USER = { username: 'user1', password: 'password123' };
const NEW_USER = { 
  username: 'testuser' + Math.floor(Math.random() * 1000), 
  email: `testuser${Math.floor(Math.random() * 1000)}@example.com`, 
  password: 'testpass123' 
};

test.describe('Login System Tests', () => {
  
  // UC-1: Authentication Tests
  test('should handle login, logout and registration flows', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await page.fill('#username', REGULAR_USER.username);
    await page.fill('#password', REGULAR_USER.password);
    await page.click('button[type="submit"]');
    await expect(page.locator('a[href="/logout"]')).toBeVisible();
    
    // logout
    await page.click('a[href="/logout"]');
    await expect(page).toHaveURL(`${BASE_URL}/login`);
    
    // registration
    await page.click('a[href="/register"]');
    await page.fill('#username', NEW_USER.username);
    await page.fill('#email', NEW_USER.email);
    await page.fill('#password', NEW_USER.password);
    await page.click('button[type="submit"]');
    
    // Verify new user can login
    await page.fill('#username', NEW_USER.username);
    await page.fill('#password', NEW_USER.password);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(`${BASE_URL}/`);
  });

  test('should show error for invalid login', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await page.fill('#username', 'wronguser');
    await page.fill('#password', 'wrongpass');
    await page.click('button[type="submit"]');
    await expect(page.locator('div[style*="color: red"]')).toBeVisible();
  });
  
  // UC-2: Profile Management Test
  test('should display and update profile information correctly', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await page.fill('#username', REGULAR_USER.username);
    await page.fill('#password', REGULAR_USER.password);
    await page.click('button[type="submit"]');
    
    // Test profile view
    await page.goto(`${BASE_URL}/profile`);
    await expect(page.locator('p', { hasText: 'Username:' })).toContainText(REGULAR_USER.username);
    
    
    // Test notification sanitization
    await page.goto(`${BASE_URL}/profile?notification=<script>alert('XSS')</script>`);
    
    // Check no alert dialog appears
    page.on('dialog', () => {
      throw new Error('XSS vulnerability detected');
    });
    await page.waitForTimeout(500);
  });
  
  // UC-3 & UC-4: Search and Status Update Tests
  test('should handle user search and status updates', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('#username', REGULAR_USER.username);
    await page.fill('#password', REGULAR_USER.password);
    await page.click('button[type="submit"]');
    
    // Test search functionality
    await page.fill('input[name="search"]', 'admin');
    await page.click('button:has-text("Search")');
    await expect(page.locator('table')).toBeVisible();
    await expect(page.locator('td', { hasText: 'admin@example.com' })).toBeVisible();
    
    await page.fill('input[name="search"]', 'nonexistentuser');
    await page.click('button:has-text("Search")');
    await expect(page.locator('p', { hasText: 'No users found' })).toBeVisible();
    
    const statusMessage = 'Testing status ' + new Date().toLocaleTimeString();
    await page.fill('input[name="message"]', statusMessage);
    await page.click('button:has-text("Update")');
    
    await expect(page.locator('div[style*="border: 1px solid #ccc"] > strong')).toBeVisible();
    await expect(page.locator('div[style*="border: 1px solid #ccc"]')).toContainText(statusMessage);
  });
  
  // UC-5: Admin Features Test
test('should enforce proper role-based access control', async ({ page }) => {
  // Test admin access
  await page.goto(`${BASE_URL}/login`);
  await page.fill('#username', ADMIN_USER.username);
  await page.fill('#password', ADMIN_USER.password);
  await page.click('button[type="submit"]');
  
  // Verify admin panel and user table are visible for admin user
  await expect(page.locator('div', { hasText: 'Admin Panel' })).toBeVisible();
  await expect(page.locator('h4', { hasText: 'All Users' })).toBeVisible();
  await expect(page.locator('table')).toBeVisible();
  
  // Logout admin
  await page.click('a[href="/logout"]');
  
  // Login as regular user
  await page.goto(`${BASE_URL}/login`);
  await page.fill('#username', REGULAR_USER.username);
  await page.fill('#password', REGULAR_USER.password);
  await page.click('button[type="submit"]');
  
  // Verify admin panel is not visible for regular user
  await expect(page.locator('div', { hasText: 'Admin Panel' })).not.toBeVisible();
  await expect(page.locator('h4', { hasText: 'All Users' })).not.toBeVisible();
});
  
  // Security Tests
  test('should properly sanitize user inputs to prevent XSS', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('#username', REGULAR_USER.username);
    await page.fill('#password', REGULAR_USER.password);
    await page.click('button[type="submit"]');
    
    // Set up alert detection
    page.on('dialog', () => {
      throw new Error('XSS vulnerability detected');
    });
    
    await page.fill('input[name="search"]', '<script>alert("XSS")</script>');
    await page.click('button:has-text("Search")');
    await page.waitForTimeout(500);
    
    await page.fill('input[name="message"]', '<script>alert("XSS")</script>');
    await page.click('button:has-text("Update")');
    await page.waitForTimeout(500);
    
    await page.goto(`${BASE_URL}/?reflectedXss=<script>alert("XSS")</script>`);
    await page.waitForTimeout(500);
  });
});