const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './', 
  testMatch: '**/*.tests.js', 
  timeout: 30000,
  expect: {
    timeout: 5000
  },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3000',
    actionTimeout: 0,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'on-first-retry'
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});