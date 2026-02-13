require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http, { cors: { origin: "*" } });
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./user'); 

// --- MIDDLEWARE ---
app.use(cors()); 
app.use(express.json()); 

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB!'))
  .catch(err => console.error('MongoDB error:', err));

// --- ROUTES ---

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ msg: "Invalid email" });
    if (await User.findOne({ username })) return res.status(400).json({ msg: "Username taken" });
    if (await User.findOne({ email })) return res.status(400).json({ msg: "Email in use" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ 
        username, email, password: hashedPassword, 
        isVerified: true, 
        verificationToken: undefined 
    });
    await newUser.save();
    res.json({ msg: "Account created successfully! Please log in." });
  } catch (err) { 
    res.status(500).json({ msg: "Server error." }); 
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ msg: "Invalid username or password." });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) { res.status(500).json({ msg: "Server error." }); }
});

const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token' });
    try { const d = jwt.verify(token, process.env.JWT_SECRET); req.user = d; next(); } 
    catch (e) { res.status(400).json({ msg: 'Invalid token' }); }
};

app.get('/my-data', auth, async (req, res) => {
    try {
        const u = await User.findById(req.user.id).populate('friends', 'username').populate('blocked', 'username'); 
        res.json({ friends: u.friends, requests: u.friendRequests, blocked: u.blocked });
    } catch(e) { res.status(500).json({msg:"Error"}); }
});

app.post('/add-friend', auth, async (req, res) => {
    try {
        const t = await User.findOne({ username: req.body.targetUsername });
        if(!t) return res.status(404).json({ msg: "User not found" });
        const s = await User.findById(req.user.id);
        t.friendRequests.push({ from: s._id, username: s.username });
        await t.save(); res.json({ msg: "Sent!" });
    } catch(e) { res.status(500).json({msg:"Error"}); }
});

app.post('/accept-friend', auth, async (req, res) => {
    try {
        const m = await User.findById(req.user.id);
        const r = await User.findById(req.body.requesterId);
        m.friends.push(r._id); r.friends.push(m._id);
        m.friendRequests = m.friendRequests.filter(x => x.from.toString() !== req.body.requesterId);
        await m.save(); await r.save(); res.json({ msg: "Added!" });
    } catch(e) { res.status(500).json({msg:"Error"}); }
});

// --- UPDATED SOCKET DM LOGIC ---

const onlineUsers = new Map(); 

io.on('connection', (socket) => {
  socket.on('identify', (id) => { 
    if(id){ 
      socket.userId = id; 
      onlineUsers.set(id, socket.id); 
      io.emit('user status change', Array.from(onlineUsers.keys())); 
    }
  });

  // User joins a specific private room
  socket.on('join room', (roomId) => {
    // Leave all rooms except personal one before joining new DM
    socket.rooms.forEach(room => {
        if(room !== socket.id) socket.leave(room);
    });
    socket.join(roomId);
    console.log(`User joined DM room: ${roomId}`);
  });

  // Handle Private Messages
  socket.on('private message', ({ roomId, sender, text }) => {
    // Emit only to the specific room (sender + receiver)
    io.to(roomId).emit('chat message', { name: sender, text });
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