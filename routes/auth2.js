const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const { generateToken, handleMongoError } = require('../utils/auth');
/**
 * Login Route
 * POST /api/auth/login
 */
router.post('/login', async (req, res) => {
  try {
    console.log('into /login');
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }
        console.log('email: ' + user.email);
        const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }

    console.log('login verified');
    
    const token = generateToken({
      id: user._id.toString(),
      username: user.username,
      email: user.email,
    });

    // Set HTTP-only cookie
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      path: '/'
    });
    console.log('object:', token);
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
    res.status(400).json({ error: errorMessage });
  }
});

/**
 * Signup Route
 * POST /api/auth/signup
 */
router.post('/signup', async (req, res) => {
  try {    
    const { username, email, password } = req.body;
    
    const user = new User({ username, email, password });
    await user.save();
    
    const token = generateToken(user._id.toString());
    
    // Set HTTP-only cookie
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      path: '/'
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
    res.status(400).json({ error: errorMessage });
  }
});

/**
 * Check Auth Status Route
 * GET /api/auth/status
 */
router.get('/status', (req, res) => {
  try {
    const authToken = req.cookies.auth_token;
    res.json({ 
      isAuthenticated: !!authToken 
    });
  } catch (error) {
    res.json({ 
      isAuthenticated: false 
    });
  }
});

router.post('/logout', (req, res) => {
    try {
      // Clear the auth_token cookie
      res.cookie('auth_token', '', {
        httpOnly: true,
        sameSite: 'strict',
        expires: new Date(0), // Expire immediately
      });
  
      console.log('Auth token deleted');
      res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
      console.error('Error during logout:', error);
      res.status(500).json({ error: 'Failed to log out' });
    }
  });

module.exports = router;