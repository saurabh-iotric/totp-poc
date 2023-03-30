var base32 = require('base32.js');
var crypto = require('crypto');
var url = require('url');
var util = require('util');
const utility = require('./utilityController')
const {BinData} = require('mongoose')
const randToken = require('rand-token')
const bcrypt = require('bcrypt');
const NodeCache = require( "node-cache" );
const myCache = new NodeCache();

exports.generateQr = async(req,res,next) => {
    try{
     
        if(!req.body.email){
            return res.status(400).json({message:"Email is required"})
        }
        //genearate a secret for a user as well as user itself
        const secret = utility.generateSecret ({length:20,qrCodes:false,email:req.body.email,app:req.body.label,issuer:req.body.company})
        console.log(secret)
        //attach secret recovery 
        const recoveryToken = randToken.generate(12);
        const recoveryHashToken = await bcrypt.hash(recoveryToken,10)
        
        //const user = await userModel.create({email:req.body.email,secret,recoveryHashToken})

        //generate Qr And Send It to User
        return res.status(200).json({qr_url:secret.otpauth_url,recoveryToken,secret:secret.base32})
    }
    catch(err){
        return res.status(200).json({message:err.message})
    }
}
//----generate otp---------------------------------------------
/*
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
}*/
exports.verifyOTP = async(req,res,next) => {
    try{
        //find user based on email
        /*const user = await userModel.findOne({email:req.body.email})
        if(!user){
            return res.status.json({message:"Unauthorised access"})
        }*/
        console.log("________REACHED FOR VERIFICATION________")
        const {secret,otp} = req.body
        console.log(secret)
        //verify OTP
        const success = utility.verifyOTP({secret,token:otp,encoding:"base32"})
        
        return res.status(200).json({success})
    }
    catch(err){
        return res.status(400).json({message:err.message})
    }
}
/*
exports.accountRecoveryInitiate = async(req,res,next) => {
    try{
        console.log("++++++++++++++++REACGED+++++++++++")
        const {email,phrase} = req.body
        console.log("__________EMAIL___________")
        const user = await userModel.findOne({email})
        if(!user){
            return res.status(400).json({
                message:"NO such user exist"
            })
        }
        console.log("Initiate - Recovert")
        console.log(user)
        //if user exist validate recovery phrase
        const isValidPhrase = await bcrypt.compare(phrase,user.recoveryHashToken)

        //if valid phrase generate a new Qr with temp secret saved in redis corresponds to userId/email

        const secret = utility.generateSecret ({length:20,qrCodes:false,email})

        console.log(secret)

        //save this secret in

        const cacheObject = {secret:secret.base32}
        //cache valid for 5minute
        myCache.set( email, cacheObject, 1000*60*5 );


        return res.status(200).json({qr_url:secret.otpauth_url})




    }
    catch(err){
        console.log(err);
        return res.status(400).json({message:err.message})
    }
}


exports.accountRecoveryVerification = async(req,res,next) => {
    try{
        const {email,otp} = req.body
        //find in cache
        const currentInMemory= myCache.get(email)

        if(!currentInMemory){
            return res.status(200).json({message:"Invalid recoverrry"})
        }

        const currentInMemorySecret = currentInMemory.secret

        //generate Otp based on currentInMemorySecret

        const verifyOTP = utility.verifyOTP({secret:currentInMemorySecret,token:otp,encoding:"base32"})
        
        if(!verifyOTP){
            return res.status(200).json({
                "message":"Invalid Recoverr"
            })
        }

        //if otp is verified successfully we will give him all the secret available for user
        const newSecrets = utility.generateSecret({length:20,qrCodes:false,email})
        console.log(newSecrets)
        //update all the secret for user and return qr for all

        //find user 
        const user = await userModel.findOneAndUpdate({email},{secret:newSecrets})

        return res.status(200).json({user})
        
    }
    catch(err){
        return res.status(400).json({message:err.message})
    }
}
*/