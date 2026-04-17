const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'ways-means-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 }
}));

const uploadDir = path.join(__dirname, 'public', 'uploads');
const dataDir = path.join(__dirname, 'data');
const captionsFile = path.join(dataDir, 'captions.json');
const usersFile = path.join(__dirname, 'users.json');

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(captionsFile)) fs.writeFileSync(captionsFile, '{}');

let users = {};
if (fs.existsSync(usersFile)) {
  users = JSON.parse(fs.readFileSync(usersFile));
} else {
  users = {
    admin: { hash: bcrypt.hashSync('ways2026', 10), role: 'admin' },
    staff1: { hash: bcrypt.hashSync('staff2026', 10), role: 'staff' },
    client1: { hash: bcrypt.hashSync('client2026', 10), role: 'client' },
  };
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

const saveUsers = () => fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
const getCaptions = () => JSON.parse(fs.readFileSync(captionsFile));
const saveCaptions = (data) => fs.writeFileSync(captionsFile, JSON.stringify(data, null, 2));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images allowed'));
  }
});

function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.sendFile(path.join(__dirname, 'login.html'));
}

function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') return next();
  res.status(403).json({ error: 'Admin only' });
}

app.get('/api/gallery', (req, res) => {
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.json([]);
    const captions = getCaptions();
    const images = files.filter(f => /\.(jpg|jpeg|png|webp|gif)$/i.test(f))
      .map(f => ({ src: '/uploads/' + f, caption: captions[f] || '' }));
    res.json(images);
  });
});

app.get('/api/user', requireAuth, (req, res) => {
  res.json({ username: req.session.user.username, role: req.session.user.role });
});

app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const userList = Object.keys(users).map(u => ({ username: u, role: users[u].role }));
  res.json(userList);
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  if (users[username]) return res.status(400).json({ error: 'User exists' });
  if (!['admin', 'staff', 'client'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  users[username] = { hash: await bcrypt.hash(password, 10), role };
  saveUsers();
  res.json({ success: true });
});

app.delete('/api/users/:username', requireAuth, requireAdmin, (req, res) => {
  const { username } = req.params;
  if (username === req.session.user.username) return res.status(400).json({ error: 'Cannot delete yourself' });
  if (!users[username]) return res.status(404).json({ error: 'User not found' });
  delete users[username];
  saveUsers();
  res.json({ success: true });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user ||!(await bcrypt.compare(password, user.hash))) {
    return res.status(401).json({ error: 'Invalid login' });
  }
  req.session.user = { username, role: user.role };
  res.json({ success: true });
});

app.post('/change-password', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  const { currentPassword, newPassword } = req.body;
  const user = users[req.session.user.username];
  if (!(await bcrypt.compare(currentPassword, user.hash))) {
    return res.status(400).json({ error: 'Current password incorrect' });
  }
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be 4+ characters' });
  }
  users[req.session.user.username].hash = await bcrypt.hash(newPassword, 10);
  saveUsers();
  res.json({ success: true });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.post('/upload', requireAuth, upload.array('photos', 10), (req, res) => {
  if (req.session.user.role === 'client') return res.status(403).json({ error: 'No permission to upload' });
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files uploaded' });
  
  const captions = getCaptions();
  const captionList = Array.isArray(req.body.captions) ? req.body.captions : [req.body.captions];
  req.files.forEach((file, i) => {
    captions[file.filename] = captionList[i] || '';
  });
  saveCaptions(captions);
  res.json({ success: true, count: req.files.length });
});

app.delete('/delete-image', requireAuth, (req, res) => {
  if (req.session.user.role === 'client') return res.status(403).json({ error: 'No permission' });
  const { filename } = req.body;
  const file = path.basename(filename);
  const filePath = path.join(uploadDir, file);
  if (filePath.startsWith(uploadDir)) {
    fs.unlink(filePath, err => {
      if (err) return res.status(500).json({ error: 'Delete failed' });
      const captions = getCaptions();
      delete captions[file];
      saveCaptions(captions);
      res.json({ success: true });
    });
  } else {
    res.status(400).json({ error: 'Invalid file' });
  }
});

app.get('/upload', requireAuth, (req, res) => {
  if (req.session.user.role === 'client') return res.status(403).send('Upload access denied');
  res.sendFile(path.join(__dirname, 'upload.html'));
});

app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Ways & Means running on port ${PORT}`));