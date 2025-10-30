const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const verifyToken = require('../middleware/authMiddleware')

const router = express.Router();

// Signup route
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check all fields
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    await newUser.save();

    res.status(201).json({ message: 'User registered successfully ' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Login route
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check all fields
    if (!email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Create JWT Token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      'secret123', // In real projects, store this in an environment variable (.env)
      { expiresIn: '24h' }
    );

    res.json({ message: 'Login successful ✅', token });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Protected route example
router.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password'); // remove password
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'Protected data accessed', user });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Protected test route
router.get("/protected", verifyToken, (req, res) => {
  res.json({
    message: `Welcome, user ${req.user.id}! You accessed a protected route.`,
  });
});

module.exports = router;