require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const csrf = require('csurf');
const winston = require('winston');
const cookieParser = require('cookie-parser');
const xss = require('xss');
const rateLimit = require('express-rate-limit');
const validator = require('validator');


const app = express();
const port = 3000;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console()
  ],
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'Strict' } }));

app.get('/v2/form', function (req, res) {
  // pass the csrfToken to the view
  res.status(201).send({ csrfToken: req.csrfToken() })
})

// 1. Secured route to prevent SQL Injection
//4. sensitive data exposure
app.get('/v2/user/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    // Use parameterized queries to avoid SQL Injection
    const result = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

//2: Fix XSS Vulnerability
let comments = []
app.get('/v2/comments', (req, res) => {
  res.send(`
    <html>
      <body>
        <h1>Comments</h1>
        <form action="/comments" method="post">
          <textarea name="comment"></textarea>
          <button type="submit">Submit</button>
        </form>
        <ul>
          ${comments.map(comment => `<li>${xss(comment)}</li>`).join('')}
        </ul>
      </body>
    </html>
  `);
});

app.post('/v2/comments', (req, res) => {
  const { comment } = req.body;
  comments.push(xss(comment)); // Sanitize input to prevent XSS
  res.redirect('/v2/comments');
});

//3. Broken Authentication Vulnerability
//8. Fix for Insufficient Logging & Monitoring
// Rate limit to prevent brute force login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts. Please try again later.',
});

app.post('/v2/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    // Fetch user from the database by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      // Log failed login attempt
      logger.warn(`Failed login attempt for email: ${email}`);
      return res.status(401).send('Invalid email or password');
    }

    const user = result.rows[0];

    // Compare the submitted password with the stored hashed password
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      // Log failed login attempt
      logger.warn(`Failed login attempt for email: ${email}`);
      return res.status(401).send('Invalid email or password');
    }

    // Log successful login
    logger.info(`Successful login for email: ${email}`);

    // Login success: send user info back (be cautious about exposing sensitive data)
    res.status(200).send(`Welcome, ${user.email}`);
  } catch (err) {
    // Log unexpected server errors
    logger.error(`Server error during login attempt for email: ${email}`, { error: err.message });
    res.status(500).send('Server error');
  }
});


// 5. Broken Access Control Vulnerability
// Middleware to authenticate user and attach the userId to the request
const authenticateUser = (req, res, next) => {
  req.userId = req.headers['userid']; // Suppose the logged-in user has userId = 1
  if (req.userId != 1) {
    return res.status(403).send('Unauthorized');
  }
  next();
};

app.put('/v2/user/password/update', authenticateUser, async (req, res) => {
  const userId = req.userId; // Get the logged-in user's ID
  const { newPassword } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Now the user can only update their own password
    const result = await pool.query(
      'UPDATE users SET password = $1 WHERE id = $2 RETURNING *',
      [hashedPassword, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('User not found');
    }

    res.status(200).send('Password updated successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


// 6. CSRF token middleware

app.post('/v2/user/email/update', async (req, res) => {
  const { userId, email } = req.body;

  try {
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [email, userId]);
    res.status(200).send('Email updated successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


// 7. Fix Insecure Deserialization Vulnerability
app.post('/v2/user/update', async (req, res) => {
  try {
    // Safely parse the user input (with validation)
    let user;
    try {
      user = JSON.parse(req.body.user);
    } catch (err) {
      return res.status(400).send('Invalid input format'); // Prevent invalid JSON
    }

    // Validate and sanitize input fields
    if (!user.email || !user.id || !validator.isEmail(user.email) || !validator.isInt(user.id.toString())) {
      return res.status(400).send('Invalid data');
    }

    // Safely process the update after validation
    const result = await pool.query('UPDATE users SET email = $1 WHERE id = $2', [user.email, user.id]);

    if (result.rowCount === 0) {
      return res.status(404).send('User not found');
    }

    res.status(200).send('User updated successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
