// Contain routes that belong to authentication
// This file is sending information back to the frontend -->

const express = require('express')
const authRouter = express.Router()
const User = require('../models/user.js')
const jwt = require('jsonwebtoken')

// Signup
// Check to see if this user exists
// send a post request to /auth/signup
// This POST requests sends a user object to the front-end
authRouter.post("/signup", (req, res, next) => {
  User.findOne({ username: req.body.username.toLowerCase() }, (err, user) => { //user info will be set to lowercase
    if(err){
      res.status(500)
      return next(err)
    }
    //If user is taken return 403 forbiden
    if(user){
      res.status(403)
      return next(new Error("That username is already taken"))
    }
    //If there is no error create user
    const newUser = new User(req.body) 
    newUser.save((err, savedUser) => {
      if(err){
        res.status(500)
        return next(err)
      }
      //Create a token for the user
                            // payload,            // secret
      const token = jwt.sign(savedUser.withoutPassword(), process.env.SECRET)
      return res.status(201).send({ token, user: savedUser.withoutPassword() })
    })
  })
})

// Login
authRouter.post("/login", (req, res, next) => {
  //make sure the user exists
  User.findOne({ username: req.body.username.toLowerCase() }, (err, user) => {
    if(err){
      res.status(500)
      return next(err)
    }
    if(!user){
      res.status(403)
      return next(new Error("Username or Password are incorrect"))
    }
    
    user.checkPassword(req.body.password, (err, isMatch) => {
      if(err){
        res.status(403)
        return next(new Error("Username or Password are incorrect"))
      }
      if(!isMatch){
        res.status(403)
        return next(new Error("Username or Password are incorrect"))
      }
      //Send token to frontend
      const token = jwt.sign(user.withoutPassword(), process.env.SECRET)
      return res.status(200).send({ token, user: user.withoutPassword() })
    })
  })
})


module.exports = authRouter

//============================================================================================================

// Route: Route is the conditionally shown component that renders some UI when its path matches
// the current URL. 

// Path: The path tells the server what the client wants and defines which section of code on the server
// should be run in order to get the correct response. The server is broken down into sections
// that correspond to a specific path.

// Query String: Is used by a specific section of the server (path) to alter a response.
// The query string is broken down into specific query parameters which can augment the way
// a server responds to a request for a specific path.

// Link: Link component is used to create links to different routes and implement
// navigation around the application.

// Switch: Switch component is used to render only the first route that matches the location
// rather than rendering all matching routes.

// JSON web token (JWT), pronounced "jot", is an open standard (RFC 7519) that defines a compact
// and self-contained way for securely transmitting information between parties as a JSON object.
// Again, JWT is a standard, meaning that all JWTs are tokens, but not all tokens are JWTs