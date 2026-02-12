const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  
  // 1. Friends List
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  
  // 2. Incoming Requests
  friendRequests: [{ 
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    username: String 
  }],

  // 3. Blocked Users (NEW)
  blocked: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

module.exports = mongoose.model('User', UserSchema);