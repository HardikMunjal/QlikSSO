"use strict";

var allowedHosts = ['http://0.0.0.0:4000','http://swift-dev.drakulaaz.com'];
module.exports = function (req,res,next) {
	console.log('fine');
	console.log(req.headers.origin);
  if(allowedHosts.indexOf(req.headers.origin) > -1){
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS,PUT');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
     }
  next();
};  



