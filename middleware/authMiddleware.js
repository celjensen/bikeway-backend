// middleware/authMiddleware.js

const jwt = require('jsonwebtoken'); // Import jsonwebtoken
require('dotenv').config();          // Ensure .env is loaded for SECRET_KEY

// This is our middleware function
function authenticateToken(req, res, next) {
    // 1. Get the token from the request header
    // Typically, tokens are sent in the Authorization header as "Bearer YOUR_TOKEN_STRING"
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token string

    if (token == null) {
        // If no token is provided, deny access
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    // 2. Verify the token
    // jwt.verify takes the token, your secret key, and a callback function
    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            // If the token is invalid (e.g., expired, tampered, or wrong secret)
            console.error("Token verification error:", err.message); // Log the specific JWT error
            return res.status(403).json({ message: 'Access denied. Invalid or expired token.' });
        }

        // If the token is valid, the 'user' object here contains the payload we signed (userId, username)
        // Attach the user information to the request object so subsequent route handlers can access it
        req.user = user;
        next(); // Call next() to pass control to the next middleware/route handler
    });
}

module.exports = authenticateToken; // Export the middleware function