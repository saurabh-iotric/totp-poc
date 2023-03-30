 /*const mongoose = require('mongoose')

 const userSchema = new mongoose.Schema({
    email:{
        type:String
    },
    secret:{
        ascii: String,
        base32:String,
        hex:String,
        otpauth_url :String
    },
    lastValidOTPTime :{
        type :Date,
        required:false
    },
    lastDigest:String,
    recoveryHashToken:String
 })

 exports.userModel = mongoose.model("User",userSchema);*/