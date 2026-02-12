require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http, { cors: { origin: "*" } });
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const User = require('./user'); 

// --- MIDDLEWARE ---
app.use(cors()); 
app.use(express.json()); 

// --- EMAIL CONFIG (Port 587 Fix) ---
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,              // Uses the modern standard port
  secure: false,          // Must be false for 587 (it upgrades to secure later)
  requireTLS: true,       // Forces a secure connection
  family: 4,              // Forces IPv4 to prevent connection errors
  auth: {
    user: 'pathproject.verify@gmail.com',
    pass: process.env.EMAIL_PASS // Your 16-digit App Password
  }
});

// Log connection status on startup
transporter.verify((error, success) => {
  if (error) {
    console.log("Email Config Error:", error);
  } else {
    console.log("Server is ready to send emails via Port 587!");
  }
});

const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; 
        next();
    } catch (e) { res.status(400).json({ msg: 'Invalid token' }); }
};

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB!'))
  .catch(err => console.error('MongoDB error:', err));

// --- ROUTES ---

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (await User.findOne({ username })) return res.status(400).json({ msg: "Username taken" });
    if (await User.findOne({ email })) return res.status(400).json({ msg: "Email in use" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const vToken = crypto.randomBytes(32).toString('hex');

    const newUser = new User({ 
        username, email, password: hashedPassword, verificationToken: vToken 
    });
    await newUser.save();

    const verifyUrl = `${process.env.BASE_URL}/verify-email/${vToken}`;
    
    await transporter.sendMail({
      from: '"Path Project" <pathproject.verify@gmail.com>',
      to: email,
      subject: "Verify your Path Account",
      html: `
        <div style="font-family: sans-serif; padding: 20px; color: #333;">
          <h2>Welcome to Path!</h2>
          <p>Please click the link below to verify your email and activate your account:</p>
          <a href="${verifyUrl}" style="padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify My Email</a>
          <br><br>
          <p>Or copy this link: ${verifyUrl}</p>
        </div>`
    });

    res.json({ msg: "Account created! Check your email to verify before logging in." });
  } catch (err) { 
    console.error("Registration Error:", err);
    res.status(500).json({ msg: "Error during registration." }); 
  }
});

app.get('/verify-email/:token', async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.status(400).send("<h1>Invalid or expired link.</h1>");
    user.isVerified = true;
    user.verificationToken = undefined; 
    await user.save();
    res.send("<h1>Email Verified!</h1><p>You can now return to the app and log in.</p>");
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ msg: "Invalid username or password." });
    }
    if (!user.isVerified) {
        return res.status(400).json({ msg: "Please verify your email before logging in!" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) { res.status(500).json({ msg: "Server error." }); }
});

// --- FRIEND SYSTEM ---

app.get('/my-data', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('friends', 'username').populate('blocked', 'username'); 
    res.json({ friends: user.friends, requests: user.friendRequests, blocked: user.blocked });
  } catch (err) { res.status(500).json({ msg: "Error fetching data" }); }
});

app.post('/add-friend', auth, async (req, res) => {
  try {
    const sender = await User.findById(req.user.id);
    const target = await User.findOne({ username: req.body.targetUsername });
    if (!target) return res.status(404).json({ msg: "User not found" });
    target.friendRequests.push({ from: sender._id, username: sender.username });
    await target.save();
    res.json({ msg: "Friend request sent!" });
  } catch (err) { res.status(500).json({ msg: "Error" }); }
});

app.post('/accept-friend', auth, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    const requester = await User.findById(req.body.requesterId);
    me.friends.push(requester._id);
    requester.friends.push(me._id);
    me.friendRequests = me.friendRequests.filter(r => r.from.toString() !== req.body.requesterId);
    await me.save(); await requester.save();
    res.json({ msg: "Friendship confirmed!" });
  } catch (err) { res.status(500).json({ msg: "Error" }); }
});

// --- SOCKET & PRESENCE ---
const onlineUsers = new Map(); 

io.on('connection', (socket) => {
  socket.on('identify', (userId) => {
    if (!userId) return;
    socket.userId = userId;
    onlineUsers.set(userId, socket.id);
    io.emit('user status change', Array.from(onlineUsers.keys()));
  });

  socket.on('chat message', (msg) => {
    io.emit('chat message', msg);
  });

  socket.on('disconnect', () => {
    setTimeout(() => {
        if (socket.userId && onlineUsers.get(socket.userId) === socket.id) {
            onlineUsers.delete(socket.userId);
            io.emit('user status change', Array.from(onlineUsers.keys()));
        }
    }, 5000);
  });
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => console.log(`Path server running on port ${PORT}`));