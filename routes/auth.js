const express = require('express');

const authController = require('../controllers/auth');
var csrf = require('csurf');
var bodyParser = require('body-parser');

const router = express.Router();

var csrfProtection = csrf({ cookie: true })
var parseForm = bodyParser.urlencoded({ extended: false })

router.get('/register', csrfProtection, (req, res) => {
    res.render('register.hbs', { csrfToken: req.csrfToken() });
});

router.get('/login', csrfProtection, (req, res) => {
    res.render('login.hbs', { csrfToken: req.csrfToken() });
});

router.post('/register', parseForm, csrfProtection, authController.register);
router.post('/login', parseForm, csrfProtection, authController.login);
router.get('/logout', authController.logout);
router.post('/set-authenticator', authController.isLoggedIn, authController.setAuthenticator);
router.post('/verify-token', authController.isLoggedIn, authController.verifyToken);
router.post('/validate-code', authController.validateToken);
router.post('/sendOTPEmail', authController.isLoggedIn, authController.sendOTPEmail);
router.post('/verifyEmailOTP', authController.isLoggedIn, authController.verifyEmailOTP);
router.post('/validateEmailOTP', authController.validateEmailOTP);
router.post('/reset-auth-settings', authController.isLoggedIn, authController.resetAuthSettings);
router.post('/reset-otp-settings', authController.isLoggedIn, authController.resetOTPSettings);
router.post('/send-reset-link', authController.sendResetLink);
router.get('/reset-password/:id', authController.resetPasswordPage);
router.post('/reset-password/:id', authController.resetPassword);
router.post('/reset-password', authController.passResetError);

module.exports = router;
