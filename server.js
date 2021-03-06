// Load required packages
var express = require('express');
var mongoose = require('mongoose');
var bodyParser = require('body-parser');
var passport = require('passport');
var session = require('express-session');
var userController = require('./controllers/user');
var clientController = require('./controllers/client');
var authController = require('./controllers/auth');
var oauth2Controller = require('./controllers/oauth2');
var beerController = require('./controllers/beer');


// Create our Express application
var app = express();

// Connect to the beerlocker MongoDB
mongoose.connect('mongodb://localhost:27017/mybeerlocker', {
  useMongoClient: true,
  /* other options */
});

// Use the body-parser package in our application
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));

// Use express session support since OAuth2orize requires it
app.use(session({
  secret: 'Super Secret Session Key',
  saveUninitialized: true,
  resave: true
}));

// Use the passport package in our application
app.use(passport.initialize());

// Create our Express router
var router = express.Router();

// Create endpoint handlers for /users
router.route('/users')
  .post(userController.postUsers)
  .get(userController.getUsers);

// Create endpoint handlers for /clients
router.route('/clients')
  .post(clientController.postClients)
  .get(clientController.getClients);

// Create endpoint handlers for oauth2 token
router.route('/oauth2/token')
  .post(authController.isClientAuthenticated, oauth2Controller.token);

// Check using access token
router.route('/restricted')
  .get(authController.isAuthenticated,function (req, res) {  	
    res.send("Yay, you successfully accessed the restricted resource!")
});

// Create endpoint handlers for /beers
router.route('/beers')
  .post(authController.isAuthenticated, beerController.postBeers)
  .get(authController.isAuthenticated, beerController.getBeers);

// Create endpoint handlers for /beers/:beer_id
router.route('/beers/:beer_id')
  .get(authController.isAuthenticated, beerController.getBeer)
  .put(authController.isAuthenticated, beerController.putBeer)
  .delete(authController.isAuthenticated, beerController.deleteBeer);

// Register all our routes with /api
app.use('/api', router);

// Start the server
app.listen(3000);