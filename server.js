// server.js

const express = require('express');
const mysql = require('mysql2/promise'); // Using the promise-based API for async/await
require('dotenv').config(); // This line loads environment variables from .env
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
const jwt = require('jsonwebtoken'); // Import jsonwebtoken for JWTs
const authenticateToken = require('./middleware/authMiddleware'); // Import your auth middleware
const cors = require('cors'); // <-- Import cors middleware
const crypto = require('crypto'); // For password reset
const mailer = require('./mailer'); // For password reset

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON body from requests
app.use(express.json());

// Middleware to parse JSON body from requests
app.use(express.json());

// Enable CORS for all routes
app.use(cors()); // <-- NEW: Use the cors middleware

// Configure the MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test the database connection when the server starts
async function testDbConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('Successfully connected to the MySQL database!');
        connection.release();
    } catch (error) {
        console.error('Failed to connect to MySQL database:', error.message);
        process.exit(1);
    }
}
testDbConnection();

//-----------------------------------------------------------------------

// BASIC ROUTE

// Handles GET requests to the root URL ('/')
app.get('/', (req, res) => {
    res.send('Welcome to the Bikeway Backend API! (Status: Online with MySQL)');
});

// Example API endpoint to get a list of users
app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, username, email, created_at, updated_at FROM users');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users from database.' });
    }
});

//-----------------------------------------------------------------------

// USER REGISTRATION ROUTE

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    // 1. Basic Validation
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Please provide username, email, and password.' });
    }

    // 2. Hash Password
    try {
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        // 3. Insert User into Database using Prepared Statements
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, password_hash]
        );

        if (result.affectedRows === 1) {
            res.status(201).json({
                message: 'User registered successfully!',
                userId: result.insertId,
                username: username,
                email: email
            });
        } else {
            res.status(500).json({ message: 'User registration failed (database error).' });
        }

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username or Email already exists.' });
        }
        console.error('Error during user registration:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

//-----------------------------------------------------------------------

// USER LOGIN ROUTE

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // 1. Basic Validation
    if (!username || !password) {
        return res.status(400).json({ message: 'Please provide username and password.' });
    }

    try {
        // 2. Find User in Database
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);

        const user = rows[0];

        if (!user) {
            // User not found
            return res.status(401).json({ message: 'Invalid credentials (username not found).' });
        }

        // 3. Compare Provided Password with Hashed Password
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            // Passwords do not match
            return res.status(401).json({ message: 'Invalid credentials (incorrect password).' });
        }

        // 4. Generate JWT upon successful login
        const payload = {
            userId: user.id,
            username: user.username
        };

        const token = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '1h' });

        // Send the token back in the response
        res.status(200).json({
            message: 'Login successful!',
            token: token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Error during user login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

//-----------------------------------------------------------------------

//USER PROFILE ROUTE

// This route will only be accessible if a valid JWT is provided
app.get('/api/profile', authenticateToken, async (req, res) => {
    // If we reach here, the token was verified, and req.user contains the payload
    try {
        // Fetch more user data if needed (e.g., from DB using req.user.userId)
        // For now, just send back the user info from the token payload
        res.json({
            message: 'Welcome to your profile!',
            user: req.user, // This contains { userId: ..., username: ... } from the JWT payload
            access: 'Granted'
        });
    } catch (error) {
        console.error('Error fetching profile data:', error);
        res.status(500).json({ message: 'Server error fetching profile.' });
    }
});

//-----------------------------------------------------------------------

// PASSWORD RESET ROUTE

// [1] User submits their email to request a reset link
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).send('Email is required.');
    }

    try {
        const [rows] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (user) {
            const token = crypto.randomBytes(32).toString('hex');
            const expires = new Date(Date.now() + 3600000); // 1 hour expiration

            await pool.execute(
                'UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?',
                [token, expires, user.id]
            );

            const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
            await mailer.sendPasswordResetEmail(email, resetLink);
        }

        // Always send a non-specific success message to prevent user enumeration
        res.status(200).send('If a matching email was found, a password reset link has been sent.');

    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).send('Server error.');
    }
});

// [2] User submits their new password with the token
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).send('Token and new password are required.');
    }

    try {
        const [rows] = await pool.execute(
            'SELECT id, password_reset_expires FROM users WHERE password_reset_token = ?',
            [token]
        );
        const user = rows[0];

        if (!user || new Date() > user.password_reset_expires) {
            return res.status(400).send('Invalid or expired token.');
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await pool.execute(
            'UPDATE users SET password_hash = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?',
            [newPasswordHash, user.id]
        );

        res.status(200).send('Password successfully reset!');

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).send('Server error.');
    }
});

//-----------------------------------------------------------------------

// Start the Express server and listen for incoming network requests
app.listen(PORT, () => {
    console.log(`Bikeway Backend API is running on http://localhost:${PORT}`);
    console.log('To stop the server, press Ctrl+C in the terminal.');
});
