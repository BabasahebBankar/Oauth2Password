// Load required packages
var mongoose = require('mongoose');

// Define our beer schema
var AccessTokenSchema   = new mongoose.Schema({
  token: String,
  expirationDate: Date,
  clientId: String,
  userId: String,
  scope: String
});

// Export the Mongoose model
module.exports = mongoose.model('accessTokens', AccessTokenSchema);