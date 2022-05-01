const express = require('express');
const authController = require('../controllers/auth');

const router = express.Router();

router.get('/', authController.isLoggedIn, (req, res) => {
    res.render('index.hbs', {
        user: req.user,
    });
});

// router.get('/register', csrfProtection, (req, res) => {
//     res.render('register.hbs', { csrfToken: req.csrfToken() });
// });

// router.get('/login', (req, res) => {
//     res.render('login.hbs');
// });

router.get('/profile', authController.isLoggedIn, (req, res) => {
    if (req.user) {
        if (req.user.is_auth_verified === 1) {
            res.render('profile.hbs', {
                user: req.user,
                auth_activated: true,
            });
        } else if (req.user.is_email_otp_verified) {
            res.render('profile.hbs', {
                user: req.user,
                otp_activated: true,
            });
        } else {
            res.render('profile.hbs', {
                user: req.user,
            });
        }
    } else {
        res.redirect('/login');
    }
});

router.get('/postArticle', authController.isLoggedIn, (req, res) => {
    if (req.user) {
        res.render('postArticle', {
            user: req.user,
        });
    } else {
        res.render('blogPosts', {
            message: 'You need to be logged in to post a new article',
        });
    }
});

router.get('/profile/authenticator-setup', (req, res) => {
    res.render('authenticator-setup.hbs', { code: '' });
});

router.get('/profile/email-otp-setup', (req, res) => {
    res.render('email-otp-setup.hbs');
});

router.get('/forgot-password', (req, res) => {
    res.render('forgot-password.hbs');
});

module.exports = router;
