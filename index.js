require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

//1: SQL Injection Vulnerability
//4. sensitive data exposure
app.get('/v1/user/:id', async (req, res) => {
  const userId = req.params.id;
  console.log(userId)
  try {
    const result = await pool.query(`SELECT * FROM users WHERE id = ${userId}`); // SQL Injection
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


//2: XSS Vulnerability
let comments = [];
app.get('/v1/comments', (req, res) => {
  res.send(`
    <html>
      <body>
        <h1>Comments</h1>
        <form action="/comments" method="post">
          <textarea name="comment"></textarea>
          <button type="submit">Submit</button>
        </form>
        <ul>
          ${comments.map(comment => `<li>${comment}</li>`).join('')}
        </ul>
      </body>
    </html>
  `);
});

app.post('/v1/comments', (req, res) => {
  const { comment } = req.body;
  comments.push(comment); // Vulnerable to XSS
  res.redirect('/comments');
});


// 3. Broken Authentication Vulnerability
app.post('/v1/register', async (req, res) => {
  console.log(req.body.password)
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);
    res.status(201).send('User registered');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

//3. Broken Authentication Vulnerability
// 8. Insufficient Logging & Monitoring
app.post('/v1/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Fetch user from the database by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      // No logging of failed login attempt

      // Vulnerability: The error message indicates whether the email exists in the system
      return res.status(401).send('Invalid email or password');
    }

    const user = result.rows[0];

    // Compare the submitted password with the stored hashed password
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      // No logging of failed login attempt

      // Vulnerability: No logging for failed attempts, no rate limiting for brute force attacks
      return res.status(401).send('Invalid email or password');
    }

    // Login success: send user info back (this could include sensitive data)
    res.status(200).send(`Welcome, ${user.email}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// 5. Broken Access Control Vulnerability
app.put('/v1/user/password/update', async (req, res) => {
  const { newPassword, userId } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // No access control check to verify that the userId belongs to the logged-in user
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

// 6. CSRF Vulnerability
app.post('/v1/user/email/update', async (req, res) => {
  const { userId, email } = req.body;

  try {
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [email, userId]);
    res.status(200).send('Email updated successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


// 7. Insecure Deserialization Vulnerability
app.post('/v1/user/update', async (req, res) => {
  try {
    // Deserializing user data directly from the request without validation
    const user = JSON.parse(req.body.user);

    // Vulnerability: no validation or sanitization of input
    const result = await pool.query('UPDATE users SET email = $1 WHERE id = $2', [user.email, user.id]);

    if (result.rowCount === 0) {
      return res.status(404).send('User not found');
    }

    res.status(200).send('User updated successfully');
  } catch (err) {
    console.error(err);
    res.status(400).send('Invalid data');
  }
});


// Start Server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
