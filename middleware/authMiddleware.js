// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
  // Get token from Authorization header
  const authHeader = req.headers['authorization']; // should be "Bearer <token>"
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  // Split "Bearer <token>"
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  try {
    // Verify token with the same secret used in login
    const decoded = jwt.verify(token, 'mysecretkey'); // must match your login secret
    req.user = decoded; // attach user info to request
    next(); // continue to the route
  } catch (err) {
    console.log('JWT Error:', err.message); // optional debug
    return res.status(403).json({ message: 'Invalid token' });
  }
};

module.exports = verifyToken;