var express = require('express');
var app = express();
var router = express.Router();
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');
var request = require('request');
var ipsec = require('./routes/ip_securer')
var https = require('https');
var http = require('http');
var fs = require('fs');
const uid = require('uid-safe');
const jwt = require('jsonwebtoken');
var request = require('request');





app.use('/', ipsec.CrossOriginHeaders);


app.use(bodyParser.urlencoded());
app.use(bodyParser.json({
  limit: '10mb'
}));

app.use(cookieParser());


app.use(router);
require('./routes')(router);
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

app.use(express.static(__dirname + '/public'));
app.set('views', __dirname + '/public/views');
app.set('view engine', 'ejs');
app.get('/qlik', function (req, res) {
  res.sendfile('public/views/index.html');
});

app.get('/qlikwebintegration', function (req, res) {
  res.sendfile('public/views/wi.html');
});

app.get('/qliktoken', async function (req, res) {


  const payload = {
    jti: uid.sync(32), // 32 bytes random string
    sub: 'random',
    subType: 'admin',
    name: 'Hardik Munjal',
    email: 'hardik.munjal@magicedtech.com',
    email_verified: true,
    // groups: ['Administrators', 'Sales', 'Marketing'],
  };

  const privateKey = fs.readFileSync('privatekey.pem');

  // kid and issuer have to match with the IDP config and the
  // audience has to be qlik.api/jwt-login-session
  const signingOptions = {
    keyid: 'bfb5b6cb-3f41-4c1a-ae79-225637204768',
    algorithm: 'RS256',
    issuer: 'xco3f3m5mieubxr.us.qlikcloud.com',
    expiresIn: '6h',
    notBefore: '0s',
    audience: 'qlik.api/login/jwt-session',
  };

  const myToken = jwt.sign(payload, privateKey, signingOptions);

  console.log(myToken);


  let logg = request.post({
    headers: {
      "content-type": "application/json",
      Authorization: `Bearer ${myToken}`,
      "qlik-web-integration-id": 'j7BQRdU8oUucp0meIsH19ajRhId8ta8t'
    },
    method: "POST",
    url: 'https://xco3f3m5mieubxr.us.qlikcloud.com/login/jwt-session?qlik-web-integration-id="j7BQRdU8oUucp0meIsH19ajRhId8ta8t"',
  }, function (error, response, body) {
    console.log(error, body);
  });
  res.json({ qliktoken: myToken });
  // //console.log(login);
})

const options = {
  key: fs.readFileSync("server.key"),
  cert: fs.readFileSync("server.cert"),
};

// Creating https server
https.createServer(options, app)
  .listen(4000, function (req, res) {
    console.log("Server started at port 4000");
  });


// https.createServer(options, app).listen(4000);
// // var server = app.listen(4000, function () {
// //   var host = server.address().address;
// //   var port = server.address().port;

// //   console.log('Example app listening at http://%s:%s', host, port);
// // });

