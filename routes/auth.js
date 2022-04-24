const express = require('express');

const authController = require('../controllers/auth');
const router = express.Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/logout', authController.logout);
router.post('/set-authenticator', authController.isLoggedIn, authController.setAuthenticator)
router.post('/verify-token', authController.isLoggedIn, authController.verifyToken)
router.post('/validate-code', authController.validateToken)


module.exports = router;
