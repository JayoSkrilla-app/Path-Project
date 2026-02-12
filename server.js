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

const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; 
        next();
    } catch (e) { res.status(400).json({ msg: 'Token is not valid' }); }
};

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB!'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (await User.findOne({ username })) return res.status(400).json({ msg: "Username taken" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.json({ msg: "Account created" });
  } catch (err) { res.status(500).json({ msg: "Error" }); }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ msg: "Invalid credentials" });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) { res.status(500).json({ msg: "Error" }); }
});

// --- FRIEND SYSTEM ---

app.get('/my-data', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .populate('friends', 'username')
      .populate('blocked', 'username'); 
    res.json({ 
      friends: user.friends, 
      requests: user.friendRequests,
      blocked: user.blocked 
    });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

app.post('/add-friend', auth, async (req, res) => {
  const { targetUsername } = req.body;
  try {
    const sender = await User.findById(req.user.id);
    const target = await User.findOne({ username: targetUsername });

    if (!target) return res.status(404).json({ msg: "User not found" });
    if (target.username === sender.username) return res.status(400).json({ msg: "Cannot add yourself" });
    
    if (target.blocked.includes(sender._id) || sender.blocked.includes(target._id)) {
        return res.status(400).json({ msg: "Unable to add user" });
    }

    if (target.friends.includes(sender._id)) return res.status(400).json({ msg: "Already friends" });
    if (target.friendRequests.some(r => r.from.equals(sender._id))) return res.status(400).json({ msg: "Request already sent" });

    target.friendRequests.push({ from: sender._id, username: sender.username });
    await target.save();
    res.json({ msg: "Friend request sent!" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

app.post('/accept-friend', auth, async (req, res) => {
  const { requesterId } = req.body;
  try {
    const me = await User.findById(req.user.id);
    const requester = await User.findById(requesterId);

    if (!requester) return res.status(404).json({ msg: "User not found" });

    me.friends.push(requester._id);
    requester.friends.push(me._id);

    me.friendRequests = me.friendRequests.filter(r => 
        r.from.toString() !== requesterId && r._id.toString() !== requesterId
    );
    
    await me.save();
    await requester.save();
    res.json({ msg: "Friend added!" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

app.post('/deny-friend', auth, async (req, res) => {
  const { requesterId } = req.body;
  try {
    const me = await User.findById(req.user.id);
    me.friendRequests = me.friendRequests.filter(r => 
        r.from.toString() !== requesterId && r._id.toString() !== requesterId
    );
    await me.save();
    res.json({ msg: "Request denied" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

app.post('/remove-friend', auth, async (req, res) => {
  const { friendId } = req.body;
  try {
    const me = await User.findById(req.user.id);
    const friend = await User.findById(friendId);

    me.friends = me.friends.filter(id => id.toString() !== friendId);
    if(friend) {
        friend.friends = friend.friends.filter(id => id.toString() !== me._id.toString());
        await friend.save();
    }
    await me.save();
    res.json({ msg: "Friend removed" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

app.post('/block-user', auth, async (req, res) => {
  const { targetId } = req.body;
  try {
    const me = await User.findById(req.user.id);
    
    if (!me.blocked.includes(targetId)) {
        me.blocked.push(targetId);
    }

    me.friends = me.friends.filter(id => id.toString() !== targetId);
    me.friendRequests = me.friendRequests.filter(r => 
        r.from.toString() !== targetId && r._id.toString() !== targetId
    );

    await me.save();
    res.json({ msg: "User blocked" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// --- SOCKET & PRESENCE TRACKING ---
const onlineUsers = new Map(); // Stores UserId -> SocketId

io.on('connection', (socket) => {
  // When a user logs in, the frontend sends their ID to 'identify' them
  socket.on('identify', (userId) => {
    socket.userId = userId;
    onlineUsers.set(userId, socket.id);
    
    // Broadcast the list of ALL online user IDs to every connected client
    io.emit('user status change', Array.from(onlineUsers.keys()));
    console.log(`User ${userId} connected.`);
  });

  socket.on('chat message', (msg) => {
    io.emit('chat message', msg);
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      // Let everyone know someone went offline
      io.emit('user status change', Array.from(onlineUsers.keys()));
      console.log(`User ${socket.userId} disconnected.`);
    }
  });
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => console.log(`Server running on port ${PORT}`));