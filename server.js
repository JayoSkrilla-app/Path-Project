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

// REGISTER & LOGIN
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

// --- FRIEND SYSTEM (UPDATED) ---

// 1. GET DASHBOARD
app.get('/my-data', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .populate('friends', 'username')
      .populate('blocked', 'username'); // Now sends blocked list too
    res.json({ 
      friends: user.friends, 
      requests: user.friendRequests,
      blocked: user.blocked 
    });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// 2. SEND REQUEST (With Block Check)
app.post('/add-friend', auth, async (req, res) => {
  const { targetUsername } = req.body;
  try {
    const sender = await User.findById(req.user.id);
    const target = await User.findOne({ username: targetUsername });

    if (!target) return res.status(404).json({ msg: "User not found" });
    if (target.username === sender.username) return res.status(400).json({ msg: "Cannot add yourself" });
    
    // BLOCK CHECK: If either person blocked the other, fail.
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

// 3. ACCEPT REQUEST
app.post('/accept-friend', auth, async (req, res) => {
  const { requesterId } = req.body;
  try {
    const me = await User.findById(req.user.id);
    const requester = await User.findById(requesterId);

    me.friends.push(requester._id);
    requester.friends.push(me._id);
    me.friendRequests = me.friendRequests.filter(r => !r.from.equals(requester._id));
    
    await me.save();
    await requester.save();
    res.json({ msg: "Friend added!" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// 4. REMOVE FRIEND (NEW)
app.post('/remove-friend', auth, async (req, res) => {
  const { friendId } = req.body;
  try {
    const me = await User.findById(req.user.id);
    const friend = await User.findById(friendId);

    // Remove from both lists
    me.friends = me.friends.filter(id => !id.equals(friendId));
    if(friend) {
        friend.friends = friend.friends.filter(id => !id.equals(me._id));
        await friend.save();
    }
    await me.save();
    res.json({ msg: "Friend removed" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// 5. BLOCK USER (NEW)
app.post('/block-user', auth, async (req, res) => {
  const { targetId } = req.body;
  try {
    const me = await User.findById(req.user.id);
    const target = await User.findById(targetId);

    // Add to block list
    if (!me.blocked.includes(targetId)) {
        me.blocked.push(targetId);
    }

    // Force remove from friends list if they are there
    me.friends = me.friends.filter(id => !id.equals(targetId));
    if(target) {
        target.friends = target.friends.filter(id => !id.equals(me._id));
        await target.save();
    }

    await me.save();
    res.json({ msg: "User blocked" });
  } catch (err) { res.status(500).json({ msg: "Server error" }); }
});

// --- SOCKET ---
io.on('connection', (socket) => {
  socket.on('chat message', (msg) => io.emit('chat message', msg));
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => console.log(`Server running on port ${PORT}`));