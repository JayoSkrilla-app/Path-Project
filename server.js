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

app.use(cors()); 
app.use(express.json()); 

mongoose.connect(process.env.MONGO_URI).then(() => console.log('DB Connected!'));

const MessageSchema = new mongoose.Schema({
  roomId: { type: String, required: true },
  sender: { type: String, required: true },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token' });
    try { const d = jwt.verify(token, process.env.JWT_SECRET); req.user = d; next(); } 
    catch (e) { res.status(400).json({ msg: 'Invalid token' }); }
};

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

// --- AUTH ---
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (await User.findOne({ username })) return res.status(400).json({ msg: "Username taken" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, isVerified: true });
    await newUser.save();
    res.json({ msg: "Success" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ msg: "Invalid" });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// --- SOCIAL LOGIC ---
app.get('/my-data', auth, async (req, res) => {
    const u = await User.findById(req.user.id).populate('friends', 'username').populate('blocked', 'username'); 
    res.json({ friends: u.friends || [], requests: u.friendRequests || [], blocked: u.blocked || [] });
});

app.get('/messages/:roomId', auth, async (req, res) => {
    try {
        const messages = await Message.find({ roomId: req.params.roomId }).sort({ timestamp: 1 });
        res.json(messages);
    } catch(e) { res.status(500).json({ msg: "Error fetching messages" }); }
});

app.post('/add-friend', auth, async (req, res) => {
    try {
        const target = await User.findOne({ username: req.body.targetUsername });
        if(!target) return res.status(404).json({ msg: "User not found." });
        const me = await User.findById(req.user.id);
        if(target._id.equals(me._id)) return res.status(400).json({ msg: "Can't add self." });
        
        const existing = target.friendRequests.find(r => r.from.toString() === me._id.toString());
        if(existing) return res.status(400).json({ msg: "Already requested." });

        target.friendRequests.push({ from: me._id, username: me.username });
        await target.save(); res.json({ msg: "Request sent!" });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

app.post('/accept-friend', auth, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        const them = await User.findById(req.body.requesterId);
        if(!them) return res.status(404).json({ msg: "User not found" });

        if(!me.friends.includes(them._id)) me.friends.push(them._id);
        if(!them.friends.includes(me._id)) them.friends.push(me._id);
        
        me.friendRequests = me.friendRequests.filter(x => x.from.toString() !== req.body.requesterId);
        await me.save(); await them.save();
        res.json({ msg: "Accepted" });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

app.post('/deny-friend', auth, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        me.friendRequests = me.friendRequests.filter(x => x.from.toString() !== req.body.requesterId);
        await me.save();
        res.json({ msg: "Denied" });
    } catch(e) { res.status(500).json({ msg: "Error" }); }
});

app.post('/remove-friend', auth, async (req, res) => {
    const me = await User.findById(req.user.id);
    const them = await User.findById(req.body.friendId);
    me.friends.pull(req.body.friendId);
    if(them) { them.friends.pull(req.user.id); await them.save(); }
    await me.save(); res.json({ msg: "Removed" });
});

app.post('/block-user', auth, async (req, res) => {
    const me = await User.findById(req.user.id);
    me.blocked.push(req.body.targetId);
    me.friends.pull(req.body.targetId);
    await me.save(); res.json({ msg: "Blocked" });
});

app.post('/unblock-user', auth, async (req, res) => {
    const me = await User.findById(req.user.id);
    me.blocked.pull(req.body.targetId);
    await me.save(); res.json({ msg: "Unblocked" });
});

// --- SOCKETS ---
const onlineUsers = new Map(); 
io.on('connection', (socket) => {
  socket.on('identify', (id) => { 
    if(id){ socket.userId = id; onlineUsers.set(id, socket.id); io.emit('user status change', Array.from(onlineUsers.keys())); }
  });
  socket.on('join room', (roomId) => {
    socket.rooms.forEach(room => { if(room !== socket.id) socket.leave(room); });
    socket.join(roomId);
  });
  
  socket.on('private message', async ({ roomId, sender, text }) => {
    try {
        const newMsg = new Message({ roomId, sender, text });
        await newMsg.save(); 
        io.to(roomId).emit('chat message', { name: sender, text });
    } catch(e) { console.error("Save error", e); }
  });

  socket.on('disconnect', () => { onlineUsers.delete(socket.userId); io.emit('user status change', Array.from(onlineUsers.keys())); });
});

http.listen(process.env.PORT || 3000);