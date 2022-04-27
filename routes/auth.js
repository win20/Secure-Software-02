const express = require('express');

const authController = require('../controllers/auth');
const router = express.Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/logout', authController.logout);
router.post('/set-authenticator', authController.isLoggedIn, authController.setAuthenticator)
router.post('/verify-token', authController.isLoggedIn, authController.verifyToken)
router.post('/validate-code', authController.validateToken)
router.post('/sendOTPEmail', authController.isLoggedIn, authController.sendOTPEmail)
router.post('/verifyEmailOTP', authController.isLoggedIn, authController.verifyEmailOTP)
router.post('/validateEmailOTP', authController.validateEmailOTP)
router.post('/reset-auth-settings', authController.isLoggedIn, authController.resetAuthSettings)
router.post('/reset-otp-settings', authController.isLoggedIn, authController.resetOTPSettings)
router.post('/send-reset-link', authController.sendResetLink)
// router.get('/reset-password/:id/:token', authController.resetPasswordPage)
router.get('/reset-password/:id', authController.resetPasswordPage)
router.post('/reset-password/:id', authController.resetPassword)
router.post('/reset-password', authController.passResetError)

module.exports = router;
