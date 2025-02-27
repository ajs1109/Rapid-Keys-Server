require('dotenv').config();
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/typing_game';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'your-secret-key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your-refresh-secret';
const NODE_ENV = process.env.NODE_ENV || 'development';

module.exports = { MONGO_URI, JWT_SECRET, TOKEN_SECRET, REFRESH_SECRET, NODE_ENV };