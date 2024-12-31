const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { MONGO_URI } = require('./config');
const authRoutes = require('./routes/auth');
const auth = require('./middleware/auth');
const User = require('./models/user');

const app = express();

mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

app.use(cors());
app.use(express.json());
app.use('/api/auth', authRoutes);

// Protected route example
app.post('/api/games/save', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    user.gamesPlayed += 1;
    if (req.body.score > user.highScore) {
      user.highScore = req.body.score;
    }
    await user.save();
    res.json({ highScore: user.highScore, gamesPlayed: user.gamesPlayed });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));