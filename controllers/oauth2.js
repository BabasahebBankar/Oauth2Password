// Load required packages
var oauth2orize = require('oauth2orize')
var crypto = require('crypto')
var bcrypt = require('bcrypt-nodejs')
var User = require('../models/user')
var Client = require('../models/client')
var AccessToken = require('../models/accessToken')
var RefreshToken = require('../models/refreshToken')

// Create OAuth 2.0 server
var server = oauth2orize.createServer();

//Resource owner password
server.exchange(oauth2orize.exchange.password(function (client, username, password, scope, done) {
    console.log(client);
    User.findOne({username: username}, function (err, user) {
        if (err) return done(err)
        if (!user) return done(null, false)
        bcrypt.compare(password, user.password, function (err, res) {
            if (!res) return done(null, false)
            
            var token = uid(20)
            var refreshToken = uid(20)
            var tokenHash = crypto.createHash('sha1').update(token).digest('hex')
            var refreshTokenHash = crypto.createHash('sha1').update(refreshToken).digest('hex')
            
            var expirationDate = new Date(new Date().getTime() + (3600 * 1000))

            // Create a new access token
		      var accessToken = new AccessToken({
		        token: tokenHash,
		        refreshToken: refreshTokenHash,
		        expirationDate: expirationDate,
		        clientId: client.id, 
		        userId: username, 
		        scope: scope
		      });
        
            accessToken.save(function (err) {
                if (err) return done(err)
                //Refresh Token Obj	
                var refreshTokenObj = new RefreshToken({			        
			        refreshToken: refreshTokenHash,			       
			        clientId: client.id, 
			        userId: username			        
			    });

                refreshTokenObj.save(function (err) {
                    if (err) return done(err)
                    done(null, token, refreshToken, {expires_in: expirationDate})
                })
            })
        })
    })
}))

//Refresh Token
server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
	console.log('in refreshToken');
	console.log(client);
    var refreshTokenHash = crypto.createHash('sha1').update(refreshToken).digest('hex')

    RefreshToken.findOne({refreshToken: refreshTokenHash}, function (err, token) {
        if (err) return done(err)
        if (!token) return done(null, false)
        if (client.id !== token.clientId) return done(null, false)
        
        var newAccessToken = uid(20)
        var accessTokenHash = crypto.createHash('sha1').update(newAccessToken).digest('hex')
        
        var expirationDate = new Date(new Date().getTime() + (3600 * 1000))        
    
        AccessToken.update({userId: token.userId}, {$set: {token: accessTokenHash, scope: scope, expirationDate: expirationDate}}, function (err) {
            if (err) return done(err)
            done(null, newAccessToken, refreshToken, {expires_in: expirationDate});
        })
    })
}))


// token endpoint
exports.token = [    
    server.token(),
    server.errorHandler()
]


/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */
function uid (len) {
  var buf = []
    , chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    , charlen = chars.length;

  for (var i = 0; i < len; ++i) {
    buf.push(chars[getRandomInt(0, charlen - 1)]);
  }

  return buf.join('');
};

/**
 * Return a random int, used by `utils.uid()`
 *
 * @param {Number} min
 * @param {Number} max
 * @return {Number}
 * @api private
 */

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

