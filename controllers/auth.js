var passport = require('passport')
var BasicStrategy = require('passport-http').BasicStrategy
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy
var BearerStrategy = require('passport-http-bearer').Strategy    
var crypto = require('crypto')
var User = require('../models/user');
var Client = require('../models/client');
var AccessToken = require('../models/accessToken');
var RefreshToken = require('../models/refreshToken');

/**
 * These strategies are used to authenticate registered OAuth clients.
 * The authentication data may be delivered using the basic authentication scheme (recommended)
 * or the client strategy, which means that the authentication data is in the body of the request.
 */
passport.use("clientBasic", new BasicStrategy(
    function (clientId, clientSecret, done) {
        Client.findOne({id: clientId}, function (err, client) {
            if (err) return done(err)
            if (!client) return done(null, false)
            //if (!client.trustedClient) return done(null, false)

            if (client.secret == clientSecret) return done(null, client)
            else return done(null, false)
        });
    }
));

passport.use("clientPassword", new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        Client.findOne({id: clientId}, function (err, client) {
            if (err) return done(err)
            if (!client) return done(null, false)
            //if (!client.trustedClient) return done(null, false)

            if (client.secret == clientSecret) return done(null, client)
            else return done(null, false)
        });
    }
));

/**
 * This strategy is used to authenticate users based on an access token (aka a
 * bearer token).
 */
passport.use("accessToken", new BearerStrategy(
    function (accessToken, done) {
        console.log(accessToken);
        var accessTokenHash = crypto.createHash('sha1').update(accessToken).digest('hex')
        AccessToken.findOne({token: accessTokenHash}, function (err, token) {
            console.log(token);
            if (err) return done(err)
            if (!token) return done(null, false)
            if (new Date() > token.expirationDate) {
                done(null, false)
            } else {
                User.findOne({username: token.userId}, function (err, user) {
                    if (err) return done(err)
                    if (!user) return done(null, false)
                    // no use of scopes for no
                    var info = { scope: '*' }
                    done(null, user, info);
                })
            }
        })
    }
))

exports.isAuthenticated = passport.authenticate(['accessToken'], { session : false });
exports.isClientAuthenticated = passport.authenticate(['clientBasic', 'clientPassword'], { session : false });