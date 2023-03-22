var base32 = require('base32.js');
var crypto = require('crypto');
var url = require('url');
var util = require('util');
const { userModel } = require('../model/userModel');
const utility = require('./utilityController')
const {BinData} = require('mongoose')
console.log(utility)
exports.generateQr = async(req,res,next) => {
    try{
        if(!req.body.email){
            return res.status(400).json({message:"Email is required"})
        }
        //genearate a secret for a user as well as user itself
        const secret = utility.generateSecret ({length:20,qr_codes:false})
        console.log(secret)
        //attach secret to user

        const user = await userModel.create({email:req.body.email,secret})

        //generate Qr And Send It to User
        return res.status(200).json({qr_url:secret.otpauth_url})
    }
    catch(err){
        return res.status(200).json({message:err.message})
    }
}
exports.generateTOTP = async(req,res,next) => {
try{
    //find user based on secret 
    const user = await userModel.findOne({'secret.base32':req.body.secret})
    console.log(user)

    //generate TOTP
    const OTP = utility.totp({secret: user.secret.base32,
        encoding: 'base32',
    })
    return res.status(200).json({OTP})

}
catch(err){
    console.log(err)
}
}
exports.verifyOTP = async(req,res,next) => {
    try{
        //find user based on email
        const user = await userModel.findOne({email:req.body.email})
        if(!user){
            return res.status.json({message:"Unauthorised access"})
        }
        console.log("_________hey__________")
        console.log(user.secret.base32)
        //verify OTP
        const verifyOTP = utility.verifyOTP({secret:user.secret.ascii,token:req.body.otp,window:2})
        console.log(verifyOTP)
        return res.status(200).json({verifyOTP})
    }
    catch(err){
        return res.status(400).json({message:err.message})
    }
}