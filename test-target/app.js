/**
 * Deliberately vulnerable NoSQL injection test target for NoSQLi Hunter.
 *
 * Endpoints:
 *   GET  /csrf                      — issues a reusable CSRF token (plain text)
 *   POST /login-json (JSON)         — strict lab-style login: requires a valid
 *                                     `csrf` field and EXACTLY one matching
 *                                     record (500 on multi-match)
 *   POST /login-url  (urlencoded)   — lenient login (findOne semantics), no CSRF
 *   GET  /search?filter=x           — reflects the filter and queries it
 *   GET  /my-account?id=x           — fake success page (auth keywords)
 *
 * Seeded users: administrator / s3cur3P@ss!  and  wiener / peter
 */
const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
const client = new MongoClient(process.env.MONGO_URL || 'mongodb://localhost:27017');
let users;

const csrfTokens = new Set();

app.use(express.urlencoded({ extended: true })); // extended=true: username[$ne] becomes an object
app.use(express.json());

app.get('/csrf', (_req, res) => {
  const t = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  csrfTokens.add(t);
  res.type('text/plain').send(t);
});

// JSON login: strict — CSRF required, exactly-one-record like the PortSwigger lab
app.post('/login-json', async (req, res) => {
  const body = req.body || {};
  if (!body.csrf || !csrfTokens.has(body.csrf)) {
    return res.status(403).send('CSRF token missing or invalid');
  }
  const found = await users.find({ username: body.username, password: body.password }).toArray();
  if (found.length === 0) return res.status(200).send('Invalid username or password');
  if (found.length !== 1) return res.status(500).send('Query returned unexpected number of records');
  res.status(302).set('Location', '/my-account?id=' + found[0].username)
    .send('Found. Redirecting to ' + found[0].username);
});

// URL-encoded login: lenient (findOne), no CSRF — good for urlencoded testing
app.post('/login-url', async (req, res) => {
  const b = req.body || {};
  const found = await users.findOne({ username: b.username, password: b.password });
  if (!found) return res.status(200).send('Invalid username or password');
  res.status(302).set('Location', '/my-account?id=' + found.username)
    .send('Found. Redirecting to ' + found.username);
});

app.get('/search', async (req, res) => {
  const filter = String(req.query.filter || '');
  const doc = await users.findOne({ username: filter });
  res.send('<html><body><h1>Search</h1><p>Results for: ' + filter + '</p><pre>'
    + (doc ? JSON.stringify({ username: doc.username }) : 'none') + '</pre></body></html>');
});

app.get('/my-account', (req, res) => {
  res.send('<html><body><h1>Welcome back!</h1><p>Account: ' + (req.query.id || '?')
    + '</p><a href="/logout">logout</a></body></html>');
});

app.get('/logout', (_req, res) => res.send('<html><body><p>You are logged out.</p></body></html>'));

(async () => {
  await client.connect();
  users = client.db().collection('users');
  await users.deleteMany({});
  await users.insertMany([
    { username: 'administrator', password: 's3cur3P@ss!' },
    { username: 'wiener',        password: 'peter' }
  ]);
  app.listen(3000, () => console.log('NoSQLi Hunter test target listening on :3000'));
})().catch(err => { console.error(err); process.exit(1); });
