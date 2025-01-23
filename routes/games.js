const express = require('express');
const mongoose = require('mongoose');
const { verifyAuth } = require('../utils/auth'); // Assume auth utilities exist
const User = require('../models/user'); // User model
const { generate } = require('random-words');

const router = express.Router();

router.post('/save', async (req, res) => {
  try {
    // Authenticate user
    const auth = await verifyAuth(req);
    if (!auth) {
      return res.status(401).json({ error: 'Please authenticate' });
    }

    const { score } = req.body;
    if (typeof score !== 'number') {
      return res.status(400).json({ error: 'Score must be a number' });
    }

    const user = await User.findById(auth.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user stats
    user.gamesPlayed += 1;
    if (score > user.highScore) {
      user.highScore = score;
    }

    await user.save();

    res.json({
      highScore: user.highScore,
      gamesPlayed: user.gamesPlayed,
    });
  } catch (error) {
    console.error('Error saving game:', error);
    res.status(500).json({ error: 'Failed to save game data' });
  }
});

router.get('/generate-text', (req, res) => {
    try {
      const wordCount = parseInt(req.query.words || '50', 10);
  
      if (isNaN(wordCount) || wordCount <= 0) {
        return res.status(400).json({ error: 'Invalid "words" query parameter' });
      }
  
      const text = generate({ exactly: wordCount, join: ' ' });
  
      res.json({ text });
    } catch (error) {
      console.error('Error generating text:', error);
      res.status(500).json({ error: 'Failed to generate text' });
    }
  });

module.exports = router;
