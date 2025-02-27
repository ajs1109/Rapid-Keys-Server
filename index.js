const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { faker } = require('@faker-js/faker');
const loremIpsum = require('lorem-ipsum');
const randomSentence = require('random-sentence');
const { MONGO_URI } = require('./config');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth3');
const authMiddleware = require('./middleware/authMiddleware');
const User = require('./models/user');
const http = require('http');
const { Server } = require('socket.io');


const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["http://localhost:3000"],
    credentials: true
  }
});

mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

app.use(cors({
  origin: ["http://localhost:3000"],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use('/api/auth', authRoutes);

// Protected route example
app.post('/api/games/save', authMiddleware, async (req, res) => {
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

app.get('/auth', (req, res, next) => {
  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  if (accessToken || refreshToken) {
    console.log('redirected');
    return res.redirect('/');
  }

  next();
});

// WebSocket Room Management
const rooms = new Map();
const userSocketMap = new Map(); // Maps userId to socketId
const socketUserMap = new Map(); // Maps socketId to userId

const loremGenerator = new loremIpsum.LoremIpsum({
  sentencesPerParagraph: {
    max: 5,
    min: 3
  },
  wordsPerSentence: {
    max: 12,
    min: 5
  }
});

// Function to generate random typing text (200 words or less)
const generateTypingText = () => {
  // Create different types of content to choose from
  const textOptions = [
    // Technology-focused text
    () => faker.lorem.paragraph(4) + ' ' + faker.hacker.phrase() + ' ' + faker.lorem.paragraph(2),
    
    // Business-focused text
    () => faker.lorem.paragraph(3) + ' ' + faker.company.catchPhrase() + ' ' + faker.lorem.paragraph(2),
    
    // Standard lorem ipsum
    () => loremGenerator.generateParagraphs(2),
    
    // More natural-sounding text
    () => faker.lorem.paragraphs(2, '\n').replace(/\n/g, ' '),
    
    // Science-focused text
    () => `The ${faker.science.chemicalElement().name} experiment showed promising results. ` + 
           faker.lorem.paragraph(4) + ` Scientists at ${faker.company.name()} continue to research this phenomenon.`
  ];
  
  // Randomly select one of the text generation methods
  const selectedGenerator = textOptions[Math.floor(Math.random() * textOptions.length)];
  let generatedText = selectedGenerator();
  
  // Ensure text is not too long (target ~150-200 words)
  const words = generatedText.split(' ');
  if (words.length > 200) {
    generatedText = words.slice(0, 180).join(' ') + '.';
  }
  
  return generatedText;
};
// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  // Authenticate user with socket
  socket.on('authenticate', async ({ userId, username }) => {
    if (userId && username) {
      userSocketMap.set(userId, socket.id);
      socketUserMap.set(socket.id, { userId, username });
      
      // Send online friends
      const onlineFriends = Array.from(socketUserMap.values())
        .filter(user => user.userId !== userId);
      socket.emit('onlineFriends', onlineFriends);
      
      // Notify others that a new user is online
      socket.broadcast.emit('userOnline', { userId, username });
    }
  });
  
  // Create a new room
  socket.on('createRoom', ({ roomId, isPrivate }) => {
    const user = socketUserMap.get(socket.id);
    if (!user) return;
    
    // Create room with unique ID if not provided
    const actualRoomId = roomId || `room_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    
    rooms.set(actualRoomId, {
      id: actualRoomId,
      isPrivate,
      players: [{ 
        socketId: socket.id, 
        userId: user.userId, 
        username: user.username,
        progress: 0,
        wpm: 0,
        accuracy: 0,
        isReady: false,
        isFinished: false
      }],
      status: 'waiting', // waiting, countdown, active, finished
      gameText: generateTypingText(),
      startTime: null,
      gameTime: 60 // Default game time (seconds)
    });
    
    // Join the socket to the room
    socket.join(actualRoomId);
    
    // Emit room details back to creator
    socket.emit('roomCreated', { 
      roomId: actualRoomId, 
      isPrivate 
    });
    
    // If public room, broadcast to everyone
    if (!isPrivate) {
      io.emit('roomAvailable', { 
        roomId: actualRoomId, 
        playerCount: 1
      });
    }
    
    console.log(`Room created: ${actualRoomId}, Private: ${isPrivate}`);
  });
  
  // Join an existing room
  socket.on('joinRoom', ({ roomId }) => {
    const user = socketUserMap.get(socket.id);
    if (!user) return;
    
    const room = rooms.get(roomId);
    if (!room) {
      socket.emit('error', { message: 'Room not found' });
      return;
    }
    
    if (room.status !== 'waiting') {
      socket.emit('error', { message: 'Game already in progress' });
      return;
    }
    
    // Add player to room
    room.players.push({ 
      socketId: socket.id, 
      userId: user.userId, 
      username: user.username,
      progress: 0,
      wpm: 0,
      accuracy: 0,
      isReady: false,
      isFinished: false
    });
    
    // Join the socket to the room
    socket.join(roomId);
    
    // Notify everyone in room about the new player
    io.to(roomId).emit('playerJoined', { 
      players: room.players.map(p => ({
        userId: p.userId,
        username: p.username,
        isReady: p.isReady
      }))
    });
    
    console.log(`User ${user.username} joined room: ${roomId}`);
  });
  
  // Player ready state change
  socket.on('playerReady', ({ roomId, ready }) => {
    const room = rooms.get(roomId);
    if (!room) return;
    
    const playerIndex = room.players.findIndex(p => p.socketId === socket.id);
    if (playerIndex === -1) return;
    
    room.players[playerIndex].isReady = ready;
    
    // Notify room about player ready state
    io.to(roomId).emit('playerReadyState', {
      userId: room.players[playerIndex].userId,
      isReady: ready
    });
    
    // Check if all players are ready
    const allReady = room.players.every(p => p.isReady);
    if (allReady && room.players.length >= 2) {
      // Start countdown
      room.status = 'countdown';
      let countdown = 3;
      
      io.to(roomId).emit('gameCountdown', { countdown });
      
      const countdownInterval = setInterval(() => {
        countdown--;
        if (countdown > 0) {
          io.to(roomId).emit('gameCountdown', { countdown });
        } else {
          clearInterval(countdownInterval);
          // Start the game
          room.status = 'active';
          room.startTime = Date.now();
          io.to(roomId).emit('gameStart', { 
            text: room.gameText,
            gameTime: room.gameTime 
          });
        }
      }, 1000);
    }
  });
  
  // Receive player progress updates
  socket.on('progressUpdate', ({ roomId, progress, wpm, accuracy }) => {
    const room = rooms.get(roomId);
    if (!room || room.status !== 'active') return;
    
    const playerIndex = room.players.findIndex(p => p.socketId === socket.id);
    if (playerIndex === -1) return;
    
    // Update player stats
    room.players[playerIndex].progress = progress;
    room.players[playerIndex].wpm = wpm;
    room.players[playerIndex].accuracy = accuracy;
    
    // Check if player finished
    if (progress >= 100 && !room.players[playerIndex].isFinished) {
      room.players[playerIndex].isFinished = true;
      
      // Calculate final position
      const position = room.players.filter(p => p.isFinished).length;
      
      // Notify player about finish position
      socket.emit('playerFinished', { position });
      
      // Notify everyone about player finishing
      io.to(roomId).emit('playerProgress', {
        userId: room.players[playerIndex].userId,
        progress: 100,
        wpm,
        accuracy,
        finished: true,
        position
      });
      
      // If all players finished, end the game
      if (room.players.every(p => p.isFinished)) {
        endGame(roomId);
      }
    } else {
      // Broadcast progress to all players in room
      io.to(roomId).emit('playerProgress', {
        userId: room.players[playerIndex].userId,
        progress,
        wpm,
        accuracy,
        finished: false
      });
    }
  });
  
  // Friend battle invitation
  socket.on('inviteFriend', ({ friendId, roomId }) => {
    const user = socketUserMap.get(socket.id);
    if (!user) return;
    
    const friendSocketId = userSocketMap.get(friendId);
    if (!friendSocketId) {
      socket.emit('error', { message: 'Friend is not online' });
      return;
    }
    
    // Send invitation to friend
    io.to(friendSocketId).emit('battleInvitation', {
      roomId,
      from: {
        userId: user.userId,
        username: user.username
      }
    });
  });
  
  // Leave room
  socket.on('leaveRoom', ({ roomId }) => {
    leaveRoom(socket, roomId);
  });
  
  // Disconnect handler
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    
    const user = socketUserMap.get(socket.id);
    if (user) {
      // Remove from user maps
      userSocketMap.delete(user.userId);
      socketUserMap.delete(socket.id);
      
      // Notify others that user is offline
      socket.broadcast.emit('userOffline', { userId: user.userId });
      
      // Leave all rooms
      for (const [roomId, room] of rooms.entries()) {
        if (room.players.some(p => p.socketId === socket.id)) {
          leaveRoom(socket, roomId);
        }
      }
    }
  });
});

// Helper function to handle a player leaving a room
function leaveRoom(socket, roomId) {
  const room = rooms.get(roomId);
  if (!room) return;
  
  const playerIndex = room.players.findIndex(p => p.socketId === socket.id);
  if (playerIndex === -1) return;
  
  const userId = room.players[playerIndex].userId;
  
  // Remove player from room
  room.players.splice(playerIndex, 1);
  
  // Leave the socket room
  socket.leave(roomId);
  
  // If room is empty, delete it
  if (room.players.length === 0) {
    rooms.delete(roomId);
    io.emit('roomClosed', { roomId });
    console.log(`Room deleted: ${roomId}`);
  } else {
    // Notify remaining players
    io.to(roomId).emit('playerLeft', { userId });
    
    // If game was active, check if we need to end it
    if (room.status === 'active' && room.players.every(p => p.isFinished)) {
      endGame(roomId);
    }
  }
}

// Helper function to end a game
function endGame(roomId) {
  const room = rooms.get(roomId);
  if (!room) return;
  
  room.status = 'finished';
  
  // Create results with player rankings
  const results = room.players
    .map(p => ({
      userId: p.userId,
      username: p.username,
      wpm: p.wpm,
      accuracy: p.accuracy,
      progress: p.progress
    }))
    .sort((a, b) => {
      // First sort by progress (completed or not)
      if (a.progress === 100 && b.progress < 100) return -1;
      if (a.progress < 100 && b.progress === 100) return 1;
      // Then by WPM for those who completed
      if (a.progress === 100 && b.progress === 100) return b.wpm - a.wpm;
      // Finally by progress percentage for those who didn't complete
      return b.progress - a.progress;
    });
  
  // Send results to all players in room
  io.to(roomId).emit('gameResults', { results });
  
  // Reset room to waiting state after 10 seconds
  setTimeout(() => {
    if (rooms.has(roomId)) {
      const room = rooms.get(roomId);
      room.status = 'waiting';
      room.players.forEach(p => {
        p.progress = 0;
        p.wpm = 0;
        p.accuracy = 0;
        p.isReady = false;
        p.isFinished = false;
      });
      
      io.to(roomId).emit('roomReset');
    }
  }, 10000);
}

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));