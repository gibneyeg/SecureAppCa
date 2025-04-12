
# Login System - Secure Branch
Security Features Implemented
1. Authentication Security

Password hashing with bcrypt
Parameterized queries for login
Session management with secure cookies
CSRF protection on all forms

2. XSS Protection

Input sanitization for all user-provided content
Output encoding in EJS templates with <%= %> instead of <%- %>
Content Security Policy implementation via Helmet
External JavaScript files for DOM manipulation

3. SQL Injection Prevention

Parameterized queries for all database operations
Input validation and sanitization
Proper error handling without revealing query details

4. Protection Against Data Exposure

Limited information in error messages
Secure logging practices
API endpoints with proper authorization

5. Access Control

Role-based access control (RBAC)
Session verification on protected routes
Admin-specific middleware for sensitive operations

How to Run

1. Install dependencies:

npm install

2. Start the server

npm start

3. Access the application

http://localhost:3000

4. Run tests-applcation must be running 

npx playwright test