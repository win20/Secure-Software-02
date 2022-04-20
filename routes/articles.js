const express = require('express')
const router = express.Router()
const Article = require('./../models/Article')
const authController = require('../controllers/auth');
const marked = require('marked')
const slugify = require('slugify')

router.get('/blog-posts', authController.isLoggedIn, async (req, res) => {
    const articles = await Article.find().sort({ createdAt: 'desc'})
    res.render('articles/blog-posts.ejs', { 
        articles: articles,
        user: req.user,
        message: ''
     })
})

router.get('/new', authController.isLoggedIn, async (req, res) => {
    const articles = await Article.find().sort({ createdAt: 'desc'})
    if (req.user) {
        res.render('articles/new.ejs', { article: new Article(), user: req.user })
    } 
    else {
        res.render('articles/blog-posts.ejs', {
            articles: articles,
            user: null,
            message: 'You need to be logged in to create a new post'
        })
    }
})

router.get('/edit/:id', authController.isLoggedIn, async (req, res) => {
    const articles = await Article.find().sort({ createdAt: 'desc'})
    const article = await Article.findById(req.params.id)

    if (req.user) {
        res.render('articles/edit.ejs', { article: article, user: req.user })
    }
    else {
        res.render('articles/blog-posts.ejs', {
            articles: articles,
            user: null,
            message: 'You need to be logged in to edit a post'
        })
    }
})

router.put('/:id', async (req, res, next) => {
    req.article = await Article.findById(req.params.id)
    next()
}, saveArticleAndRedirect('edit.ejs'))

router.delete('/:id', authController.isLoggedIn, async (req, res) => {
    const articles = await Article.find().sort({ createdAt: 'desc'})
    if (req.user) {
        await Article.findByIdAndDelete(req.params.id)
        res.redirect('/articles/blog-posts')
    }
    else {
        res.render('articles/blog-posts.ejs', {
            articles: articles,
            user: null,
            message: 'You need to be logged in to delete a post'
        })
    }
})

router.get('/:slug', authController.isLoggedIn, async (req, res) => {
    const article = await Article.findOne({ slug: req.params.slug })

    if (article == null) res.redirect('/articles/blog-posts.ejs')
    else res.render('articles/show.ejs', { article: article, user: req.user })
})

router.post('/', (req, res, next) => {
    req.article = new Article()
    next()
}, saveArticleAndRedirect('new.ejs'))

// Used when creating new article or editing existing article,
// gathers all data from body and saves it to database
function saveArticleAndRedirect(path) {
    return async (req, res) => {
        let article = req.article
        
        article.title = req.body.title
        article.description = req.body.description
        article.markdown = req.body.markdown
        
        try {
            article = await article.save()
            res.redirect(`/articles/${article.slug}`)
        }
        catch (e) {
            res.render(`articles/${path}`, { article: article })
        }
    }
}

module.exports = router