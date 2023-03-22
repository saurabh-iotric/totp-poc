const router = require('express').Router()
const userController = require('../controller/userController')
router.post('/generate-qr',userController.generateQr)
router.post('/generate-otp',userController.generateTOTP)
router.post('/verify-otp',userController.verifyOTP)

module.exports = router;