const express = require('express');
const session = require('express-session')
const router = express.Router();
const authController = require('../controllers/auth');
const Article = require('../models/Article');

router.get('/', authController.isLoggedIn, (req, res) => {
    res.render('index.hbs', {
        user: req.user
    });
});

router.get('/register', (req, res) => {
    res.render('register.hbs');
});

router.get('/login', (req, res) => {
    res.render('login.hbs');
});

router.get('/profile', authController.isLoggedIn, (req, res) => {
    if (req.user) {
        res.render('profile.hbs', {
            user: req.user
        });
    }
    else {
        res.redirect('/login.hbs');
    }
});

router.get('/postArticle', authController.isLoggedIn, (req, res) => {
    if (req.user) {
        res.render('postArticle', {
            user: req.user
        });
    }
    else {
        res.render('blogPosts', {
            message: 'You need to be logged in to post a new article'
        });
    }
});

module.exports = router;
