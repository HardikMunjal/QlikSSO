'use strict';

var qlikauth = require('./qlik-auth');
var request = require('request');
var ejs = require('ejs');
var fs = require('fs');
var qendpoint = require('../config/endpoint');




var qlik = {


  proxyRedirectFromQlik: function(req, res, next) {

    if(global.user_id && global.user_directory){
      var profile = {
       'UserDirectory': global.user_directory
      }
    profile.UserId = global.user_id;
    qlikauth.requestTicket(req, res, profile);
    }
    else{
      res.send('Either your token has been expired or you have not provided the valid credential');
      return;
    }
  },

  userExistingSession: function(req, res, next) {

    
    if(!req.params.user_id && !req.params.user_directory){
     res.send('User must have to pass directory and user_id', 400);
     return;
    }

    

    var profile = {
      UserDirectory: req.params.user_directory
    }

    profile.UserId = req.params.user_id;
    console.log('session checking');
    qlikauth.getUserSession(req, res, profile);
  
    },

  getUsersList: function(req, res, next) {

    
    var profile = {
      UserDirectory: 'ss'
    }

    profile.UserId = 'ss';
    console.log('users fetching');
    qlikauth.getUsersDetails(req, res, profile);
  
    },

  userQlikTicket: function(req, res, next) {

    var destination = qendpoint.qlik_proxy_pt+"hub/";
    

    if(!req.params.user_id && !req.params.user_directory){
     res.send('User must have to pass directory and user_id', 400);
     return;
    }


    if(req.query.open){
      destination = req.query.open;

      if(destination.indexOf(qendpoint.qlik_proxy_pt) == -1){
        res.send("Invalid URL in open parameter",400);
        return;
      }
      if(destination == qendpoint.qlik_proxy_pt+"hub/"){
        res.send("To open hub, You need to exclude / from the end",400);
        return;
      }
    }
    
    global.user_id = req.params.user_id.trim();
    global.user_directory = req.params.user_directory.trim(); 
    
    console.log('************ MAKING REQUEST ************');
    getTicket(destination);
    
    function getTicket(url){
      
      var dynamicTicket={};
      request(url, function (error, response, body) {
        console.log(error);
        dynamicTicket=body;
        if (!error && response.statusCode == 200) {
          var bodyObject =JSON.parse(body);
          if(bodyObject.UserId.toUpperCase().trim() != req.params.user_id.toUpperCase().trim()){
           console.log('######################### coming at danger end ############################')
           console.log(bodyObject);

           console.log(req.params.user_id);
           global.user_id = req.params.user_id.trim();
           global.user_directory = req.params.user_directory.trim();
           if(req.query.open){
            destination = req.query.open
           }else{
             destination= qendpoint.qlik_proxy_pt+"hub/"
           }
            
           getTicket(destination);
          } else {
          console.log('Ticket Rqst successfully cmpltd for '+bodyObject.UserId); 

          if(bodyObject.TargetUri != qendpoint.qlik_proxy_pt+"hub/"){
            res.render('qlikhub.ejs',{data: dynamicTicket});
            return;
          }
          
          res.json(bodyObject);
          global.user_id = 'null';
          global.user_directory = 'null';
          return;
          }
          }
          
       })

    }
        
  }
};
module.exports = qlik;