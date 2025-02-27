const jwt = require('jsonwebtoken');
const { TOKEN_SECRET, REFRESH_SECRET } = require('../config');
const User = require('../models/user');

const verifyToken = (token, secret) => {
  try {
    return jwt.verify(token, secret);
  } catch (error) {
    console.log('error in verification:', error);
    return null;
  }
};

const authMiddleware = async (req, res, next) => {
  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  console.log('into auth middleware:', req.cookies);

  if (!accessToken && !refreshToken) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  let decodedAccessToken = verifyToken(accessToken, TOKEN_SECRET);
  let decodedRefreshToken = verifyToken(refreshToken, REFRESH_SECRET);

  console.log('decoded:', decodedAccessToken, decodedRefreshToken);

  if (decodedAccessToken) {
    req.user = decodedAccessToken.user;
    return next();
  }

  if (decodedRefreshToken) {
    const user = await User.findById(decodedRefreshToken.user._id);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const newAccessToken = jwt.sign({ user }, TOKEN_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign({ user }, REFRESH_SECRET, { expiresIn: '7d' });

    res.cookie('access_token', newAccessToken, {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
      path: '/'
    });

    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });

    req.user = decodedRefreshToken.user;
    return next();
  }

  return res.status(401).json({ error: 'Unauthorized' });
};

module.exports = authMiddleware;