const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { handleMongoError } = require('../middleware/auth');
const { JWT_SECRET } = require('../config');

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

router.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const user = new User({ username, email, password });
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id }, 
      JWT_SECRET
    );
    res.status(201).json({ token, user: { id: user._id, username, email } });
  } catch (error) {
    let errorMessage = handleMongoError(error).message;
    res.status(400).json({ error: errorMessage });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id }, 
      JWT_SECRET
    );
    res.json({ token, user: { id: user._id, username: user.username, email } });
  } catch (error) {
    let errorMessage = handleMongoError(error).message;
    res.status(400).json({ error: errorMessage });
  }
});

// Protected route example
router.post('/games/save', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    user.gamesPlayed += 1;
    if (req.body.score > user.highScore) {
      user.highScore = req.body.score;
    }
    await user.save();
    res.json({ highScore: user.highScore, gamesPlayed: user.gamesPlayed });
  } catch (error) {
    let errorMessage = handleMongoError(error).message;
    res.status(400).json({ error: errorMessage });
  }
});

module.exports = router;