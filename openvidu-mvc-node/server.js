/* CONFIGURATION */

const OpenVidu = require('openvidu-node-client').OpenVidu;
const OpenViduRole = require('openvidu-node-client').OpenViduRole;
const RecordingMode = require('openvidu-node-client').RecordingMode;
const Recording = require('openvidu-node-client').Recording;

// Check launch arguments: must receive openvidu-server URL and the secret
if (process.argv.length != 4) {
    console.log("Usage: node " + __filename + " OPENVIDU_URL OPENVIDU_SECRET");
    process.exit(-1);
}
// For demo purposes we ignore self-signed certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

// Node imports
const express = require('express');
const fs = require('fs');
const helmet = require('helmet');
const session = require('express-session');
const https = require('https');
const bodyParser = require('body-parser'); // Pull information from HTML POST (express4)
const jwt = require('jwt-simple');
const moment = require('moment'); // for date in jwt token

const app = express(); // Create our app with express

app.set('jwtTokenSecret', 'YOUR_SECRET_STRING');
app.use(helmet());
// Server configuration
app.use(session({
   saveUninitialized: true,
   resave: false,
   secret: 'MY_SECRET'
}));
app.use(express.static(__dirname + '/public')); // Set the static files location
app.use(bodyParser.urlencoded({
   'extended': 'true'
})); // Parse application/x-www-form-urlencoded
app.use(bodyParser.json()); // Parse application/json
//app.use(bodyParser.json({
 //   type: 'application/vnd.api+json'
//})); // Parse application/vnd.api+json as json
app.set('view engine', 'ejs'); // Embedded JavaScript as template engine

// Listen (start app with node server.js)
const options = {
    key: fs.readFileSync('openvidukey.pem'),
    cert: fs.readFileSync('openviducert.pem')
};
https.createServer(options, app).listen(5000);


// Mock database
var users = new Map();
function addUser(name, pass, role) { 
   users.set(name, {
      name: name,
      pass: pass,
      role: role,
      logged: false,
      rooms: []
   });
}
addUser("p1", "p1pass", OpenViduRole.PUBLISHER);
addUser("p3", "p3pass", OpenViduRole.PUBLISHER);
addUser("s1", "s1pass", OpenViduRole.SUBSCRIBER);

// jwt auth handler checks token and returns the user 
function getUser(req, res, next) {
  const token = req.session.access_token || (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
  console.log(token);
  if (token) {
    try {
      const decoded = jwt.decode(token, app.get('jwtTokenSecret'));
      if (decoded.exp <= Date.now()) {
        req.session.destroy();
        res.render('login', {
           error: 'Access token has expired',
        });
      } else if (!users.has(decoded.name) || !users.get(decoded.name).logged) {
        req.session.destroy();
        res.render('login', {
           error: 'You are not logged in',
        });
      } else {
        req.user = users.get(decoded.name);
        req.session.access_token = token;
        next();
      }
    } catch (err) {
      console.log(err);
      req.session.destroy();
      res.render('login', {
           error: 'Bad Token',
      });
    }
  } else {
    next();
  }
}

// middle to ensure the user is identified
function userFound(req, res, next) {
  if(req.user) {
    next();
  } else {
    req.session.destroy();
    res.render('login', {
       error: 'You must login first',
    });
  }
}


// jwt token generator
function jwtToken(name) {
  const expires = moment().add(7, 'days').valueOf();
  const token = jwt.encode({
    name: name,  
    exp: expires
  }, app.get('jwtTokenSecret'));
  users.get(name).logged = true;
  return token;
}

// Environment variable: URL where our OpenVidu server is listening
const OPENVIDU_URL = process.argv[2];
// Environment variable: secret shared with our OpenVidu server
const OPENVIDU_SECRET = process.argv[3];

// Entrypoint to OpenVidu Node Client SDK
const OV = new OpenVidu(OPENVIDU_URL, OPENVIDU_SECRET);
console.log("App listening on port 5000");


/* CONFIGURATION */



/* REST API */
app.get('/login', getUser, getLoginScreen);
app.post('/login', loginUser);

// [getUser, userFound],

function getLoginScreen(req, res) {
  if(req.user) res.redirect('dashboard');
  else res.render('login');
}

function loginUser(req, res) {
  // Retrieve params from POST body
  const name = req.body.name;
  const pass = req.body.pass;
  console.log("Logging in | {user, pass}={" + name + ", " + pass + "}");
  if (login(name, pass)) { // Correct user-pass
      // Validate session and return OK 
      // Value stored in req.session allows us to identify the user in future requests
      console.log("'" + name + "' has logged in");
      req.session.access_token = jwtToken(name);
      console.log("'" + req.session.access_token + "' Token given ");
      res.redirect('dashboard'); 
  } else { // Wrong user-pass
      // Invalidate session and return index template
      if(res.session) res.session.destroy();
      res.render('login', {
         error: 'Invalid Credentials',
      });
  }
}

app.post('/logout', [getUser, userFound], logoutUser);

function logoutUser(req, res) {
   req.user.logged = false;
   req.session.destroy();
   res.redirect('login');
}

app.get('/dashboard', [getUser, userFound], dashboardController);

function dashboardController(req, res) {
   var payload = {
      name: req.user.name, 
      rooms: req.user.rooms
   };
   console.log(payload);
   res.render('dashboard', payload); 
}

var rooms = {};
app.post('/create-room', [getUser, userFound], createRoom);

function createRoom(req,  res) {
    const tokenOptions = {
      role: req.user.role,
      data: JSON.stringify({ serverData: req.user })
    }
    const roomName = req.body.room_name || "Default Room Name";
    const sessionProperties = {
      recordingMode: RecordingMode.ALWAYS,
      defaultOutputMode: Recording.OutputMode.INDIVIDUAL
    } 
    OV.createSession(sessionProperties)
       .then(session => { 
           // rooms contain all running sessions 
           const sessionId = session.getSessionId; 
           rooms[sessionId] = {
              session: session,
              name: roomName,
              creator: req.user.name,
              created_on: Date.now(),
              tokens_subscribed: []
           }
           req.user.rooms[sessionId] = {
              name: roomName
           }
           // Generate a new token asynchronously with the recently created tokenOptions
           session.generateToken(tokenOptions)
               .then(token => {
                   // Store the new token in the collection of tokens
                   rooms[sessionId].tokens_subscribed.push(token);
                   // add room to user object as created
                   req.user.rooms[sessionId].token = token; 
                   res.session.msg = "New session created";
                   res.redirect('dashboard');
               })
               .catch(error => {
                   console.error(error);
                   res.session.error = "error creating token for the session";
                   res.redirect('dashboard');
               });
       })
       .catch(error => {
           console.error(error);
           res.session.error = "error creating session";
           res.redirect('dashboard');
       });
}

//app.post("/close-room", jwtAuth, closeRoom);

function closeRoom(req, res) {
  const reqRoomId = req.body.room_id;
  if (rooms.reqRoomId && req.user.name == rooms.reqRoomId.creator) {
    const session = rooms.reqRoomId.session;
    session.close()
      .then(() => {
         delete rooms.reqRoomId;
         res.send("Room closed successfully");
       })
      .catch(error => {
         console.error(error);
         res.status(400).send("Error closing room");
      }); 
  } else {
     res.status(400).send("Invalid room_id or Forbidden");
  }
}


//app.post("/join-room", jwtAuth, joinRoom);

function joinRoom(req, res) {
  const reqRoomId = req.body.room_id;
  if (rooms.reqRoomId) {
    const session = rooms.reqRoomId.session;
    const tokenOptions = {
      role: req.user.role,
      data: JSON.stringify({ serverData: req.user })
    }
    session.generateToken(tokenOptions)
        .then(token => {
            // Append the new token in the collection of tokens
            rooms[reqRoomId].tokens_subscribed.push(token);
            // Send token as response
            res.send({ 
              token: token
            });
        })
        .catch(error => {
            console.error(error);
            res.send({ 
              error: "error creating token for the session", 
              code: 5
            });
        });

  } else {
     res.status(400).send("Invalid room_id");
  }
}

//app.post("/leave-room", jwtAuth, leaveRoom);

function leaveRoom(req, res) {
  const reqRoomId = req.body.room_id;
  if (rooms.reqRoomId) {
    var tokens = rooms.reqRoomId.tokens_subscribed;
    const index = tokens.indexOf(req.user);

    // If the token exists
    if (index !== -1) {
      // Token removed
      tokens.splice(index, 1);
    } else {
      res.status(400).send("Invalid room_id");
    }
    if (tokens.length == 0) {
        // Last user left: session must be removed
        delete rooms.reqRoomId; 
    }
    res.send("Room Left");
  } else {
     res.status(400).send("Invalid room_id");
  }
}


/* REST API */



/* AUXILIARY METHODS */

function login(name, pass) {
    return (name && pass && users.has(name) &&
        users.get(name).pass == pass);
}

function getBasicAuth() {
    return 'Basic ' + (new Buffer('OPENVIDUAPP:' + OPENVIDU_SECRET).toString('base64'));
}

/* AUXILIARY METHODS */
