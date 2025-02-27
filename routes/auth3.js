// auth.js
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user'); 
const authMiddleware = require('../middleware/authMiddleware');
const { TOKEN_SECRET, REFRESH_SECRET, NODE_ENV } = require('../config');

// Cookie options
const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/'
};

const ACCESS_COOKIE_OPTIONS = {
  secure: NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000, // 15 minutes
  path: '/'
};

const generateAccessToken = (user, res) => {
  const accessToken = jwt.sign(
    { user: user },
    TOKEN_SECRET,
    { expiresIn: '15m' }
  );
  res.cookie('access_token', accessToken, ACCESS_COOKIE_OPTIONS);
  return accessToken;
}

const generateRefreshToken = (user, res) => { 
  const refreshToken = jwt.sign(
    { user: user },
    REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie('refresh_token', refreshToken, REFRESH_COOKIE_OPTIONS);
  return refreshToken;
}

const clearCookies = (res) => {
  res.clearCookie('refresh_token');
  res.clearCookie('access_token');
}

// Middleware to verify access token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, TOKEN_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired access token' });
  }
};

// Register new user
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ 
        message: 'Please provide all required fields' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Hash password
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    const accessToken = generateAccessToken(user, res);
    generateRefreshToken(user, res);

    // Send response
    res.status(201).json({
      accessToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Registration failed' });
  }
});

// Login user
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    user.password = ''; // Don't send password in response
    const accessToken = generateAccessToken(user, res);
    generateRefreshToken(user, res);

    // Send response
    res.status(201).json({
      accessToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});

//User Info
router.get('/user', (req, res) => {
  var refreshToken = req.cookies.refresh_token;
  try {
    console.log('refrsh token /user router get',refreshToken);
    var decodedAccessToken = jwt.verify(refreshToken || '', REFRESH_SECRET);
    return res.status(200).json(decodedAccessToken);
  } catch (error) {
    console.log('error', error);
    return res.status(401).json({message: 'not found' });
  }
})

router.post('/verify-token', (req, res) => {
  const { refreshToken } = req.body;
  try{
    var decodedRefreshToken = jwt.verify(refreshToken || '', REFRESH_SECRET);
    console.log('in refresh token', decodedRefreshToken);
    generateAccessToken(decodedRefreshToken?.user, res);
    console.log('access token is valid');
    generateRefreshToken(decodedRefreshToken?.user, res);
    console.log('refresh token is valid');
    return res.status(200).json({ message: 'Refresh token is valid', user: decodedRefreshToken?.user });
  }
  catch(err){
    console.error('Refresh token not valid:', err);
  }

  return res.status(200).json({ message: 'Invalid token' });
})

// Refresh access token
router.post('/refresh', (req, res) => {
  try {
    console.log('into /refresh', req.body);
    const token = req.body.token;
    const decoded = jwt.verify(token, REFRESH_SECRET);
    if(decoded){
    const accessToken = generateAccessToken(decoded?.user, res);
    console.log('access token:', accessToken);
    generateRefreshToken(decoded?.user, res);
    return res.status(201).json({ message: 'Access token refreshed', user: decoded.user, accessToken });
    }

    return res.status(401).json({ message: 'Invalid refresh token' });
  } catch (error) {
    clearCookies(res);
    res.status(401).json({ message: 'Invalid refresh token' });
  }
});

router.get('/refresh', async (req, res) => {
  const refreshToken = req.cookies?.refresh_token;
  const accessToken = req.cookies?.access_token;
  console.log('/refresh', refreshToken, accessToken);
  if(!refreshToken){
    return res.status(401).json({ message: 'No refresh token found' });
  }
  try{
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    if (!decoded) {
      clearCookies(res);
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const user = await User.findById(decoded.user._id);
    if (!user) {
      clearCookies(res);
      return res.status(401).json({ message: 'User not found' });
    }

    const accessToken = generateAccessToken(user, res);
    generateRefreshToken(user, res);

    return res.status(200).json({ message: 'Access token refreshed', accessToken });
  } catch (error) {
    console.error('Refresh token error:', error);
    clearCookies(res);
    res.status(401).json({ message: 'Invalid refresh token' });
  } 
});

// Logout user
router.post('/logout', (req, res) => {
  clearCookies(res);
  res.json({ message: 'Logged out successfully' });
});

router.get('/me', (req, res) => {
  console.log('from /me access token:' , req.cookies);
  res.json({ token: req.cookies?.access_token });
})

module.exports = router;