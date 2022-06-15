'use strict';

var allowedHosts = ['10.98.100.59','http://staging2.myhcl.com','10.97.92.35','10.33.86.5','10.112.17.97','10.33.62.77','10.33.66.31','10.33.86.12','10.97.92.138','10.33.86.10'];



                    
var ipsec = {

   whitelistIp: function(req, res, next) {

    if(req.connection.remoteAddress){
      var remoteIp = req.connection.remoteAddress;
      if (remoteIp.substr(0, 7) == "::ffff:") {
        remoteIp = remoteIp.substr(7)
      }
    }  

    if(req.headers.origin){
      var remoteIp = req.headers.origin;
    }

    if(allowedHosts.indexOf(remoteIp) > -1){
       next();
    }
    else{
       res.end('Access is denied, Your IP is not trusted');
     }
    },

    CrossOriginHeaders : function (req, res, next) {

      var date = new Date();
      console.log("**************"+req.path+"*************");
      console.log(date);
      console.log('Allowing coming IP(req.headers.origin)',  req.headers.origin);
      console.log('Client Remote Address(req.connection.remoteAddress)', req.connection.remoteAddress);
      // if(allowedHosts.indexOf(req.headers.origin) > -1){
      // }
      res.header('Access-Control-Allow-Origin','*');
      res.header('Access-Control-Allow-Credentials', true);
      res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS,PUT');
      res.header('Access-Control-Allow-Headers', 'Content-Type');
      next();
    }
  };


module.exports = ipsec;