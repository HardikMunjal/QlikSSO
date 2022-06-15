var request = require('request');
var sys = require('sys');
var open = require("open");
var ejs = require('ejs');
var fs = require('fs');
var qlik = require('./qlik');
var ipsec = require('./ip_securer');



module.exports = function (app) {


app.get('/authenticate', qlik.proxyRedirectFromQlik);
//app.all('/scr/*',ipsec.whitelistIp);
app.get('/scr/session/user/:user_directory/:user_id', qlik.userExistingSession);
app.get('/scr/ticket/user/:user_directory/:user_id',qlik.userQlikTicket);

};
