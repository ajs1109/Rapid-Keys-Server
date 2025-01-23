const jwt = require('jsonwebtoken');
const jose = require('jose');
const { JWT_SECRET } = require('../config');

const AUTH_COOKIE = 'auth_token';

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
  path: '/'
};

const authUtils = {
  setAuthCookie: (res, token) => {
    res.cookie(AUTH_COOKIE, token, cookieOptions);
  },

  removeAuthCookie: (res) => {
    res.clearCookie(AUTH_COOKIE, { path: '/' });
  },

  handleAuthResponse: (data, status = 200) => {
    if (status >= 400) {
      throw new Error(data.message || 'Authentication failed');
    }
    return data;
  }
};


const decodeToken = async (token) => {
  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      console.error('JWT_SECRET is not defined');
      return null;
    }

    const secretBytes = new TextEncoder().encode(secret);
    const { payload } = await jose.jwtVerify(token, secretBytes);

    return {
      id: payload.id,
      username: payload.username,
      email: payload.email,
      iat: payload.iat,
      exp: payload.exp
    };
  } catch (error) {
    console.error('Token decode error:', error);
    return null;
  }
};


const getCookie = (req, name) => {
  return req.cookies[name];
};

const generateToken = (payload) => {
  const secret = JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  return jwt.sign(payload, secret, {
    expiresIn: '7d',
  });
};

const handleMongoError = (error) => {
  if (error.name === 'ValidationError') {
    const field = Object.keys(error.errors)[0];
    return {
      message: error.errors[field].message,
      field,
      code: 400
    };
  }

  if (error.code === 11000) {
    const field = Object.keys(error.keyPattern)[0];
    return {
      message: `${field} already exists`,
      field,
      code: 409
    };
  }

  return {
    message: error.message || 'An unexpected error occurred',
    code: 500
  };
};

async function verifyAuth(req) {
    try {
      const authHeader = req.headers.authorization;
      const token =
        authHeader && authHeader.startsWith('Bearer ')
          ? authHeader.split(' ')[1]
          : req.cookies?.auth_token;
  
      if (!token) {
        return null; // No token provided
      }
  
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      return { userId: decoded.userId }; // Assuming the token contains a `userId` field
    } catch (error) {
      console.error('Authentication error:', error.message);
      return null; // Invalid or expired token
    }
  }

module.exports = {
  AUTH_COOKIE,
  authUtils,
  decodeToken,
  getCookie,
  generateToken,
  handleMongoError,
  verifyAuth
};