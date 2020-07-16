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
//var session = require('express-session');
const https = require('https');
const bodyParser = require('body-parser'); // Pull information from HTML POST (express4)
const jwt = require('jwt-simple');
const moment = require('moment'); // for date in jwt token

const app = express(); // Create our app with express

app.set('jwtTokenSecret', 'YOUR_SECRET_STRING');
app.use(helmet());
// Server configuration
//app.use(session({
 //   saveUninitialized: true,
  //  resave: false,
   // secret: 'MY_SECRET'
//}));
//app.use(express.static(__dirname + '/public')); // Set the static files location
app.use(bodyParser.urlencoded({
   'extended': 'true'
})); // Parse application/x-www-form-urlencoded
app.use(bodyParser.json()); // Parse application/json
//app.use(bodyParser.json({
 //   type: 'application/vnd.api+json'
//})); // Parse application/vnd.api+json as json
//app.set('view engine', 'ejs'); // Embedded JavaScript as template engine

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
      pass: pass,
      role: role,
      logged: false
   });
}
addUser("p1", "p1pass", OpenViduRole.PUBLISHER);
addUser("p3", "p3pass", OpenViduRole.PUBLISHER);
addUser("s1", "s1pass", OpenViduRole.SUBSCRIBER);

// jwt auth handler checks token and returns the user 
function jwtauth(req, res, next) {
  const token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
//  console.log(res.body);
  if (token) {
  try {
      const decoded = jwt.decode(token, app.get('jwtTokenSecret'));
      if (decoded.exp <= Date.now()) {
        res.status(400).send('Access token has expired');
      } else if (!users.has(decoded.name) || !users.get(decoded.name).logged) {
        res.status(400).send('You are not logged in');
      } else {
        req.user = users.get(decoded.name);
        next();
      }
    } catch (err) {
      console.log("error while parsing a token");
      res.status(400).send("Bad Token");
    }
  } else {
      res.status(400).send("Forbidden. No access token found");
  } 
}

// jwt token generator
function jwttoken(name) {
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

// Collection to pair session names with OpenVidu Session objects
var mapSessions = {};
// Collection to pair session names with tokens
var mapSessionNamesTokens = {};

console.log("App listening on port 5000");

/* CONFIGURATION */



/* REST API */

app.post('/login', loginUser);
// app.get('/', loginController);

function loginUser(req, res) {
  // Retrieve params from POST body
  const name = req.body.name;
  const pass = req.body.pass;
  console.log("Logging in | {user, pass}={" + name + ", " + pass + "}");
  if (login(name, pass)){ // Correct user-pass
      // Validate session and return OK 
      // Value stored in req.session allows us to identify the user in future requests
      console.log("'" + name + "' has logged in");
      res.send({
         token: jwttoken(name),
      });
 } else { // Wrong user-pass
      // Invalidate session and return index template
      console.log("'" + name + "' invalid credentials");
      res.status(400).send({
         error: "invalid credentials",
         code: 2
      });
  }
}

app.post('/logout', jwtauth, logoutUser);

function logoutUser(req, res) {
    if(req.user) {
      req.user.logged = false;
      res.send('you are logged out now');
    } else {
      res.status(400).send('You are already not logged in');
    }
}

var rooms = {};
app.post('/create-room', createRoom);

function createRoom(req, res) {
  req.user = users.get("p1");
  if(req.user) {
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

           // Generate a new token asynchronously with the recently created tokenOptions
           session.generateToken(tokenOptions)
               .then(token => {
                   // Store the new token in the collection of tokens
                   rooms[sessionId].tokens_subscribed.push(token);
                   // Send token and sessionId as response
                   res.send({ 
                     token: token,
                     room_id: sessionId
                   });
               })
               .catch(error => {
                   console.error(error);
                   res.send({ 
                     error: "error creating token for the session", 
                     session_id: sessionId,
                     code: 3
                   });
               });
       })
       .catch(error => {
           console.error(error);
           res.send({ 
             error: "error creating session",
             code: 4
           });
       });
  }
}

app.post("/close-room", jwtAuth, closeRoom);

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


app.post("/join-room", jwtAuth, joinRoom);

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

app.post("/leave-room", jwtAuth, leaveRoom);

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
