// Import JWT_SECRET from environment
const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    // Use process.env.JWT_SECRET directly since we can't import the constant
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    req.userData = { email: decodedToken.email };
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Authentication failed' });
  }
};

module.exports = auth;