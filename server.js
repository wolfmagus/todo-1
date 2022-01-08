//1. The go between for the front end client and the back end server
const express = require('express')
const app = express()
require('dotenv').config()
const morgan = require('morgan')
const mongoose = require('mongoose')
const expressJwt = require('express-jwt')
const port = process.env.PORT || 9000;//newly added for heroku
const secret = process.env.SECRET || " cat moon kelp shoe "//newly added for heroku
const path = require("path")//newly added for heroku

//Middleware for express and morgan
app.use(express.json())
app.use(morgan('dev'))
app.use(express.static(path.join(__dirname, "client", "build")))//newly added for heroku
//connect to mongodb
mongoose.connect(
  'mongodb://localhost:27017/user-authentication',
  //'process.env.MONGODB_URI',//newly added for heroku
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
    useFindAndModify: false
  },
  () => console.log('Connected to the DB')
)
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true });//newly added for heroku
// '/auth' is the end point used for login and signup
// /signup or /login can be attached to /auth to send data
app.use('/auth', require('./routes/authRouter.js'))
// app.use('/api', expressJwt({secret: process.env.SECRET, algorithms: ['HS256']}))
app.use('/api', expressJwt({secret: secret, algorithms: ['HS256']}))//newly added for heroku
app.use('/api/todo', require('./routes/todoRouter.js'))
//Handle errors server side
app.use((err, req, res, next) => {
  console.log(err)
  if(err.name === "UnauthorizedError"){
    res.status(err.status)
  }
  return res.send({errMsg: err.message})
})

app.get("*", (req, res) => {//newly added for heroku
  res.sendFile(path.join(__dirname, "client", "build", "index.html"));//newly added for heroku
});//newly added for heroku

app.listen(port, () => {//used to say 9000 instead of port
  console.log(`Server is running on local port 9000`)
})