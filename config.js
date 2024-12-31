require('dotenv').config();
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/typing_game';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

module.exports = { MONGO_URI, JWT_SECRET };