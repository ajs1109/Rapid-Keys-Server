const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');

const auth = (req, res, next) => {
  try {
    // Check if Authorization header exists
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      return res.status(401).json({ 
        error: 'No authentication token provided' 
      });
    }

    // Verify token format
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'Invalid token format. Must be: Bearer <token>' 
      });
    }

    const token = authHeader.replace('Bearer ', '');
    
    // Verify token with a more secure secret
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Add user data to request
    req.userId = decoded.userId;
    req.token = token; // Optionally store token for later use
    
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ 
        error: 'Invalid or expired token' 
      });
    }
    
    return res.status(500).json({ 
      error: 'Authentication error' 
    });
  }
};

/**
 * Handles MongoDB errors and converts them to user-friendly responses
 * @param {Error} error - MongoDB error object
 * @returns {Object} Formatted error response
 */
const handleMongoError = (error) => {
  // Handle duplicate key errors
  if (error.code === 11000) {
    const field = Object.keys(error.keyPattern)[0];
    const value = error.keyValue[field];
    return {
      status: 409,
      message: `An account with this ${field} (${value}) already exists.`,
      field: field,
      code: 'DUPLICATE_ENTRY'
    };
  }
  
  // Handle validation errors
  if (error.name === 'ValidationError') {
    const field = Object.keys(error.errors)[0];
    return {
      status: 400,
      message: error.errors[field].message,
      field: field,
      code: 'VALIDATION_ERROR'
    };
  }
  
  // Handle cast errors (invalid ObjectId, etc.)
  if (error.name === 'CastError') {
    return {
      status: 400,
      message: `Invalid ${error.path}: ${error.value}`,
      field: error.path,
      code: 'INVALID_FORMAT'
    };
  }
  
  // Default error response
  return {
    status: 500,
    message: 'An unexpected error occurred',
    field: null,
    code: 'INTERNAL_ERROR'
  };
};

module.exports = { auth, handleMongoError };