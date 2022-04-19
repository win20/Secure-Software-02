const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const async = require('hbs/lib/async');
const cookieParser = require('cookie-parser');
const { promisify } = require('util')

const { request } = require('express');

var currentUser 

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});


exports.register = (req, res) => {
    // console.log(req.body);

    const { name, email, password, passwordConfirm } = req.body;

    // note: '?' helps with SQL injection
    db.query('SELECT email FROM users WHERE email = ?', [ email ], async (error, results) => {
        if (error) {
            console.log(error);
        } 

        if (results.length > 0) {
            return res.render('register.hbs', {
                message: 'That email is already in use'
            });
        }
        else if (password != passwordConfirm) {
            return res.render('register.hbs', {
                message: 'The passwords do not match'
            });
        }

        // hash password
        let hashedPassword = await bcrypt.hash(password, 8);

        // send data to data base
        db.query('INSERT INTO users SET ? ', { name: name, email: email, password: hashedPassword }, (error, results) => {
            if (error) {
                console.log(error);
            }
            else {
                return res.render('register.hbs', {
                    message: 'User Registered'
                });
            }
        });
    });
}

exports.login = async (req, res) => {
    // console.log(req.body)

    try {
        const { email, password } = req.body

        if (!email || !password) {
            return res.status(400).render('login.hbs', {
                message: 'Please provide an email and password'
            })
        }

        db.query('SELECT * FROM users WHERE email = ?', [ email ], async (error, results) => {
            // console.log(results)
            if (!results || !(await bcrypt.compare(password, results[0].password))) {
                res.status(401).render('login.hbs', {
                    message: 'Email or password is incorrect'
                })
            }
            else {
                const id = results[0].id

                const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES_IN
                })

                // console.log('The token is:' + token)
                const cookieOptions = {
                    expires: new Date(Date.now + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                    httpOnly: true
                }

                res.cookie('jwt', token, cookieOptions)
                res.status(200).redirect('/')          
            }
        })
    }
    catch (error) {
        console.log(error)
    }
}

exports.isLoggedIn = async (req, res, next) => {
    // console.log(req.cookies)
    if (req.cookies.jwt) {
        try {
            // verify the token
            const decoded = await promisify(jwt.verify) (req.cookies.jwt, process.env.JWT_SECRET)
            // console.log(decoded)

            // check is the user still exists
            db.query('SELECT * FROM users WHERE id = ?', [ decoded.id ], (error, result) => {
                // console.log(result)

                if (!result) {
                    return next()
                }

                req.user = result[0]
                currentUser = result[0]
                return next()
            })
        }
        catch (error) {
            console.log(error)
            return next()
        }
    }
    else next()
} 

exports.logout = async (req, res) => {
    res.clearCookie('jwt')
    res.status(200).redirect('/')
}

exports.postArticle = (req, res) => {

    const { title, description, article } = req.body
    var author = currentUser.name

    db.query('INSERT INTO blogposts SET ? ', { title: title, description: description, article: article, author: author }, (error, results) => {
        if (error) {
            console.log(error);
        }
        else {
            return res.render('postArticle.hbs', {
                message: 'Article posted successfully'
            });
        }
    });
}


exports.getBlogPosts = (req, res, next) => {

    db.query('SELECT * FROM blogposts', (error, results) => {
        
        if (error){
            console.log(error)
        }

        if (!results) {
            return next()
        }
        
        // console.log(results)
        req.posts = results[2]
        console.log(req.posts)
        
        return next()         
    })  
}