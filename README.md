# SecureAppCa-Insecure branch

## Vulnerabilities Introduced

### 1. SQL Injection
- Direct string concatenation in SQL queries
- No parameterized queries
- User input directly incorporated into SQL statements

### 2. XSS (Cross-Site Scripting)
- **Reflected XSS**: Search functionality that reflects user input without sanitization
- **DOM-based XSS**: JavaScript that inserts user input into the DOM
- **Stored XSS**: Task comments that store and display unfiltered HTML/JavaScript

### 3. Sensitive Data Exposure
- Detailed error messages exposed to users
- Database queries logged to console
- Task data exposed in client-side JavaScript

## How to Run

1. Install dependencies:
```bash
npm install