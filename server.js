/** server.js
 * Server for an example of sessions
 */

// Constants
const PORT = 3000;

// Requires
var fs = require('fs');
var http = require('http');
var encryption = require('./lib/encryption');
var parseCookie = require('./lib/cookie-parser');
var urlencoded = require('./lib/form-urlencoded');
var server = new http.Server(handleRequest);


/** @function handleRequest
 * The webserver's request handling function
 * @param {http.incomingRequest} req - the request object
 * @param {http.serverResponse} res - the response object
 */
function handleRequest(req, res) {

  // We need to determine if there is a logged-in user.
  // We'll check for a session cookie
  var cookies = parseCookie(req.headers.cookie);

  // To better protect against manipulation of the session
  // cookie, we encrypt it before sending it to the
  // client.  Therefore, the cookie they send back is
  // likewise encrypted, and must be decrypted before
  // we can make sense of it.
  var cryptedSession = cookies["cryptsession"];

  // There may not yet be a session
  if(!cryptedSession) {
    // if not, set req.session to be empty
    req.session = {}
  } else {
    // if so, the session is encrypted, and must be decrypted
    var sessionData = encryption.decipher(cryptedSession);
    // further, it is in JSON form, so parse it and set the
    // req.session object to be its parsed value
    req.session = JSON.parse(sessionData);
  }

  switch(req.url) {
    // Serve the index file
    case '/':
    case '/index.html':
      fs.readFile('public/index.html', function(err, data){
        if(err){
        }
        res.setHeader("Content-Type", "text/html");
        res.end(data);
      });
      break;

    case '/login':
      if(req.method == 'GET') {
        // For GET requests, serve the login page
        fs.readFile('public/login.html', function(err, data){
          if(err){
          }
          res.setHeader("Content-Type", "text/html");
          res.end(data);
        });
      } else {
        // For POST requests, parse the urlencoded body
        urlencoded(req, res, function(req, res){
          var username = req.body.username;
          var password = req.body.password;
          // Evaluate the username/password
          if(username == 'simon' && password == 'simple'){
            // matching password & username - log the user in
            // by creating the session object
            var session = {username: username};
            // JSON encode the session object
            var sessionData = JSON.stringify(session);
            // Encrypt the session data
            var sessionCrypt = encryption.encipher(sessionData);
            // And send it to the client as a session cookie
            res.setHeader("Set-Cookie", ["cryptsession=" + sessionCrypt + "; session;"]);
            // Finally, redirect back to the index
            res.statusCode = 302;
            res.setHeader("Location", "/index.html");
            res.end();
          } else {
            // Not a username/password match, redirect to
            res.statusCode = 302;
            res.setHeader("Location", "/login");
            res.end();
          }
        });
      }
      break;

    case '/logout':
      // Clear the session by flushing its value
      res.setHeader("Set-Cookie", ["cryptsession="]);
      // Redirect back to the index
      res.statusCode = 302;
      res.setHeader("Location", "/index.html");
      res.end();
      break;

    case '/one':
      // Make sure the user is logged in before serving
      // this resource
      loginRequired(req, res, function(req,res){
        res.end("You can access this resource (ONE)!");
      });
      break;

    case '/two':
      // Make sure the user is logged in before serving
      // this resource
      loginRequired(req, res, function(req,res){
        res.end("You can access this resource (TWO)!");
      });
      break;

  }
}


/** @function loginRequired
 * A helper function to make sure a user is logged
 * in.  If they are not logged in, the user is
 * redirected to the login page.  If they are,
 * the next request handler is invoked.
 * @param {http.IncomingRequest} req - the request object
 * @param {http.serverResponse} res - the response object
 * @param {function} next - the request handler to invoke if
 * a user is logged in.
 */
function loginRequired(req, res, next) {
  // Make sure both a session exists and contains a
  // username (if so, we have a logged-in user)
  if(!(req.session && req.session.username)) {
    // Redirect to the login page
    res.statusCode = 302;
    res.setHeader('Location', '/login');
    return res.end();
  }
  // Pass control to the next request handler
  next(req, res);
}

// Start the server
server.listen(PORT, function(){
  console.log("Listening on port:", PORT);
});
