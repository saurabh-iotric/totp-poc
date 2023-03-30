const router = require('express').Router()
const userController = require('../controller/userController')
router.post('/generate-qr',userController.generateQr)
//router.post('/generate-otp',userController.generateTOTP)
router.post('/verify-otp',userController.verifyOTP)
/*
router.post('/initiate-recovery',userController.accountRecoveryInitiate)
router.put('/verify-recovery',userController.accountRecoveryVerification)
*/

module.exports = router;