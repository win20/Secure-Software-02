// Imports
const mysql = require('mysql')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const async = require('hbs/lib/async')
const cookieParser = require('cookie-parser')
const { promisify } = require('util')
const { request, response } = require('express')
const fetch = require('isomorphic-fetch')

// Store current user if logged in
var currentUser 

// Connect sql
const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
})

// Takes data from front-end, validates and encrypts it if needed and sends to the database
// Returns: message object to front end with different value depending on outcome
exports.register = (req, res) => {
    const { name, email, password, passwordConfirm } = req.body

    const response_key = req.body['g-recaptcha-response']
    const secret_key = process.env.CAPTCHA_SECRET

    const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secret_key}&response=${response_key}`

    fetch (url, { 
        method: 'post' 
    })
    .then((response) => response.json())
    .then((google_response) => {
        if (google_response.success == true) {
            // sql query to find user using email, returns error and results to use as params in the nested function
            // note: '?', parameterized query helps against SQL injection
            db.query('SELECT email FROM users WHERE email = ?', [ email ], async (error, results) => {
                if (error) {
                    console.log(error)
                } 

                if (results.length > 0) {
                    return res.render('register.hbs', {
                        message: 'That email is already in use'
                    })
                }
                else if (password != passwordConfirm) {
                    return res.render('register.hbs', {
                        message: 'The passwords do not match'
                    })
                }

                // hash password
                let hashedPassword = await bcrypt.hash(password, 8)

                // send data to database
                db.query('INSERT INTO users SET ? ', { name: name, email: email, password: hashedPassword }, (error, results) => {
                    if (error) {
                        console.log(error)
                    }
                    else {
                        return res.render('register.hbs', {
                            successMessage: 'User Registered'
                        })
                    }
                })
            })
          }
          else {
            return res.render('register.hbs', {
                message: 'Failed Captcha.'
            })
          }
      })
      .catch((error) => {
          return res.json({ error })
      })
}

// Validates user inputs and compares it with data in database to authenticate user,
// once logged in a cookie using web tokens is created to store the users data while the session is active.
// Returns: sends messages to front-end as well as user data if they manage to log in.
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body

        if (!email || !password) {
            return res.status(400).render('login.hbs', {
                message: 'Please provide an email and password'
            })
        }

        // note: sends same message regardless of email failure or password failure or both
        db.query('SELECT * FROM users WHERE email = ?', [ email ], async (error, results) => {
            if (results < 1) {
                res.status(401).render('login.hbs', {message: 'Email or password is incorrect'})
            }
            else if (!(await bcrypt.compare(password, results[0].password))) {
                res.status(401).render('login.hbs', {message: 'Email or password is incorrect'})
            }
            else {
                const id = results[0].id
                const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES_IN
                })
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


// Used whenever a page needs to know if the user is logged in or not,
// decodes web token data to find user and send data to front-end 
exports.isLoggedIn = async (req, res, next) => {
    if (req.cookies.jwt) {
        try {
            // verify the token
            const decoded = await promisify(jwt.verify) (req.cookies.jwt, process.env.JWT_SECRET)

            // check is the user still exists
            db.query('SELECT * FROM users WHERE id = ?', [ decoded.id ], (error, result) => {

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

// Delete user cookie and redirects to home page
exports.logout = async (req, res) => {
    res.clearCookie('jwt')
    res.status(200).redirect('/')
}

