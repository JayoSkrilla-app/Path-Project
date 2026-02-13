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

// --- AUTH MIDDLEWARE ---
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        res.status(400).json({ msg: 'Token is not valid' });
    }
};

// --- ROUTES ---

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

// REGISTER
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ msg: "Invalid email" });
    if (await User.findOne({ username })) return res.status(400).json({ msg: "Username taken" });
    if (await User.findOne({ email })) return res.status(400).json({ msg: "Email in use" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ 
        username, email, password: hashedPassword, 
        isVerified: true 
    });
    await newUser.save();
    res.json({ msg: "Account created!" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// LOGIN
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ msg: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// GET MY DATA
app.get('/my-data', auth, async (req, res) => {
    try {
        const u = await User.findById(req.user.id)
            .populate('friends', 'username')
            .populate('blocked', 'username'); 
        res.json({ friends: u.friends, requests: u.friendRequests, blocked: u.blocked });
    } catch(e) { res.status(500).json({ msg: "Error fetching data" }); }
});

// FRIEND REQUESTS
app.post('/add-friend', auth, async (req, res) => {
    try {
        const target = await User.findOne({ username: req.body.targetUsername });
        if(!target) return res.status(404).json({ msg: "User not found" });
        if(target._id.toString() === req.user.id) return res.status(400).json({ msg: "Cannot add yourself" });
        
        const me = await User.findById(req.user.id);
        
        if(target.friendRequests.some(r => r.from.toString() === me._id.toString())) return res.json({ msg: "Request already sent" });

        target.friendRequests.push({ from: me._id, username: me.username });
        await target.save(); 
        res.json({ msg: "Request Sent!" });
    } catch(e) { res.status(500).json({ msg: "Server error" }); }
});

app.post('/accept-friend', auth, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        const them = await User.findById(req.body.requesterId);
        if(!them) return res.status(404).json({ msg: "User not found" });

        me.friends.push(them._id); 
        them.friends.push(me._id);
        me.friendRequests = me.friendRequests.filter(x => x.from.toString() !== req.body.requesterId);
        
        await me.save(); 
        await them.save(); 
        res.json({ msg: "Friend added!" });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

// RESTORED: DENY REQUEST
app.post('/deny-friend', auth, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        me.friendRequests = me.friendRequests.filter(x => x.from.toString() !== req.body.requesterId);
        await me.save();
        res.json({ msg: "Denied." });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

// RESTORED: REMOVE FRIEND
app.post('/remove-friend', auth, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        const them = await User.findById(req.body.friendId);
        me.friends.pull(req.body.friendId);
        if(them) them.friends.pull(req.user.id);
        await me.save();
        if(them) await them.save();
        res.json({ msg: "Removed." });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

// RESTORED: BLOCK/UNBLOCK
app.post('/block-user', auth, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        if(!me.blocked.includes(req.body.targetId)) me.blocked.push(req.body.targetId);
        me.friends.pull(req.body.targetId); 
        await me.save();
        res.json({ msg: "Blocked." });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

app.post('/unblock-user', auth, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        me.blocked.pull(req.body.targetId);
        await me.save();
        res.json({ msg: "Unblocked." });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

// --- SOCKET.IO PRIVATE CHAT LOGIC ---

const onlineUsers = new Map(); 

io.on('connection', (socket) => {
  socket.on('identify', (id) => { 
    if(id){ 
      socket.userId = id; 
      onlineUsers.set(id, socket.id); 
      io.emit('user status change', Array.from(onlineUsers.keys())); 
    }
  });

  socket.on('join room', (roomId) => {

    socket.rooms.forEach(room => {
        if(room !== socket.id) socket.leave(room);
    });
    socket.join(roomId);
    console.log(`User ${socket.userId} joined room: ${roomId}`);
  });

  socket.on('private message', ({ roomId, sender, text }) => {

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
http.listen(PORT, () => console.log(`Path server active on port ${PORT}`));