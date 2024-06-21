const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const Message = require('./models/Message');
const ws = require('ws');
const fs = require('fs');

dotenv.config();
const app = express();
const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

// Database connection
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB', err));

// Middleware
app.use('/uploads', express.static(__dirname + '/uploads'));
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'https://chatfront-omega.vercel.app',
  credentials: true,
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Helper function to get user data from request
async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, jwtSecret, (err, userData) => {
        if (err) reject(err);
        resolve(userData);
      });
    } else {
      reject('No token');
    }
  });
}

// Routes
app.get('/test', (req, res) => {
  res.json('test ok');
});

app.get('/messages/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const userData = await getUserDataFromRequest(req);
    const ourUserId = userData.userId;
    const messages = await Message.find({
      sender: { $in: [userId, ourUserId] },
      recipient: { $in: [userId, ourUserId] },
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/people', async (req, res) => {
  const users = await User.find({}, { '_id': 1, username: 1 });
  res.json(users);
});

app.get('/profile', (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, jwtSecret, (err, userData) => {
      if (err) return res.status(500).json('Token verification failed');
      res.json(userData);
    });
  } else {
    res.status(401).json('No token');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const foundUser = await User.findOne({ username });
  if (foundUser) {
    const passOk = bcrypt.compareSync(password, foundUser.password);
    if (passOk) {
      jwt.sign({ userId: foundUser._id, username }, jwtSecret, (err, token) => {
        res.cookie('token', token, { sameSite: 'none', secure: true }).json({
          id: foundUser._id,
        });
      });
    } else {
      res.status(401).json('Invalid credentials');
    }
  } else {
    res.status(401).json('Invalid credentials');
  }
});

app.post('/logout', (req, res) => {
  res.cookie('token', '', { sameSite: 'none', secure: true }).json('ok');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
    });
    jwt.sign({ userId: createdUser._id, username }, jwtSecret, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
        id: createdUser._id,
      });
    });
  } catch (err) {
    res.status(500).json('error');
  }
});

// Start server
const server = app.listen(4040, () => {
  console.log('Server listening on port 4040');
});

// WebSocket setup
const wss = new ws.Server({ server, maxPayload: 50 * 1024 * 1024 }); // 50MB payload limit
wss.on('connection', (connection, req) => {

  function notifyAboutOnlinePeople() {
    [...wss.clients].forEach(client => {
      client.send(JSON.stringify({
        online: [...wss.clients].map(c => ({ userId: c.userId, username: c.username })),
      }));
    });
  }

  connection.isAlive = true;

  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
    }, 1000);
  }, 5000);

  connection.on('pong', () => {
    clearTimeout(connection.deathTimer);
  });

  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies.split(';').find(str => str.trim().startsWith('token='));
    if (tokenCookieString) {
      const token = tokenCookieString.split('=')[1];
      if (token) {
        jwt.verify(token, jwtSecret, (err, userData) => {
          if (err) throw err;
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
          notifyAboutOnlinePeople(); // Notify after setting user data
        });
      }
    }
  }

  connection.on('message', async (message) => {
    try {
      const messageData = JSON.parse(message.toString());
      const { recipient, text, file } = messageData;
      let filename = null;
      if (file) {
        const parts = file.name.split('.');
        const ext = parts[parts.length - 1];
        filename = Date.now() + '.' + ext;
        const path = __dirname + '/uploads/' + filename;
        const bufferData = Buffer.from(file.data.split(',')[1], 'base64');
        fs.writeFile(path, bufferData, () => {
          console.log('file saved:' + path);
        });
      }
      if (recipient && (text || file)) {
        const messageDoc = await Message.create({
          sender: connection.userId,
          recipient,
          text,
          file: file ? filename : null,
        });
        [...wss.clients]
          .filter(c => c.userId === recipient)
          .forEach(c => c.send(JSON.stringify({
            text,
            sender: connection.userId,
            recipient,
            file: file ? filename : null,
            _id: messageDoc._id,
          })));
      }
    } catch (error) {
      console.error('Failed to process message:', error);
      connection.send(JSON.stringify({ error: 'Failed to process message' }));
    }
  });

  connection.on('error', (error) => {
    console.error('WebSocket error:', error);
  });

  notifyAboutOnlinePeople();
});
