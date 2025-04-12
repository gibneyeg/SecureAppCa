Login System - Insecure Branch
Vulnerabilities Introduced
1. SQL Injection

Direct string concatenation in SQL queries
No parameterized queries
Example vulnerability: login endpoint using string concatenation

2. XSS (Cross-Site Scripting)

Reflected XSS: Error messages displayed without sanitization using <%- error %>
DOM-based XSS: JavaScript directly inserting query parameters into innerHTML
Stored XSS: Status updates stored and displayed without sanitization

3. CSRF Vulnerabilities

No CSRF tokens on forms
No SameSite cookie attributes
No protection against cross-site request forgery

4. Authentication Weaknesses

Plaintext password storage
Weak session management
No proper logout functionality

5. Sensitive Data Exposure

Admin API exposing all user data including passwords
Detailed error messages exposed to users
Database query details logged to console

How to Run

1. Install dependencies:

npm install

2. Start the server:

3. npm start

Access the application

http://localhost:3000
