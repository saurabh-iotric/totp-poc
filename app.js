const express = require('express')
//const mongoose = require('mongoose')
const userRouter = require('./route/userRoute')
const app = express()
const cors = require('cors')
//body parser middleware
app.use(express.json())
app.use(cors())


//------------------mounting route-----------------------------

app.use('/api/user',userRouter)

app.listen(8100,() => console.log("server has been started on 8100"))