const express = require('express')
const mongoose = require('mongoose')
const userRouter = require('./route/userRoute')
const app = express()
//body parser middleware
app.use(express.json())

//------------------connecting to database--------------------
mongoose.connect("mongodb://127.0.0.1:27017/mc-auth").then(res => console.log("database sucessfully connected")).catch(err => console.log(err.message))


//------------------mounting route-----------------------------
app.use('/api/user',userRouter)

app.listen(8100,() => console.log("server has been started on 8100"))