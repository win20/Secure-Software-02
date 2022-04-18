const express = require('express');
const session = require('express-session')
const router = express.Router();
const authController = require('../controllers/auth');


router.get('/', authController.isLoggedIn, (req, res) => {

    res.render('index', {
        user: req.user
    });
});

router.get('/register', (req, res) => {
    res.render('register');
});

router.get('/login', (req, res) => {
    res.render('login');
});

router.get('/profile', authController.isLoggedIn, (req, res) => {
    if (req.user) {
        res.render('profile', {
            user: req.user
        });
    }
    else {
        res.redirect('/login');
    }
});

router.get('/blogPosts', authController.isLoggedIn, authController.getBlogPosts, (req, res) => {
    
    res.render('blogPosts', {
        user: req.user,
        posts: req.posts
    });
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
