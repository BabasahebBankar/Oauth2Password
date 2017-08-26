// Load required packages
var mongoose = require('mongoose');

// Define our beer schema
var RefreshTokenSchema   = new mongoose.Schema({
  refreshToken: String,  
  clientId: String,
  userId: String  
});

// Export the Mongoose model
module.exports = mongoose.model('refreshTokens', RefreshTokenSchema);