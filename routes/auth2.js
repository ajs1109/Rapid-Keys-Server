const express = require('express');
const router = express.Router();
const User = require('../models/user');
const { generateToken, handleMongoError, decodeToken } = require('../utils/auth');
const auth = require('../middleware/auth');
const bcrypt = require('bcryptjs');
const { TOKEN_SECRET, NODE_ENV } = process.env;

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/'
};

// Login Route
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('/login email pass:', email, password);
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken({
      id: user._id.toString(),
      username: user.username,
      email: user.email
    });
    
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    res.json({
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    const errorMessage = handleMongoError(error).message;
    res.status(400).json({ message: errorMessage });
  }
});

// Signup Route
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const user = new User({ username, email, password });
    await user.save();
    
    const token = generateToken({
      id: user._id.toString(),
      username: user.username,
      email: user.email
    });
    
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    res.status(201).json({
      token,
      user: {
        id: user._id.toString(),
        username,
        email
      }
    });
  } catch (error) {
    const errorMessage = handleMongoError(error).message;
    res.status(400).json({ message: errorMessage });
  }
});

// Logout Route
router.post('/logout', (req, res) => {
  res.clearCookie('auth_token', {
    httpOnly: true,
    sameSite: 'strict',
    path: '/'
  });
  
  res.json({ message: 'Logged out successfully' });
});

// Get Current User Route
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(401).json(null);
    }
    
    res.json({
      id: user._id,
      username: user.username,
      email: user.email
    });
  } catch (error) {
    console.error('Error getting current user:', error);
    res.status(401).json(null);
  }
});

module.exports = router;