/* eslint-disable prefer-destructuring */
/* eslint-disable no-shadow */
/* eslint-disable no-promise-executor-return */
/* eslint-disable consistent-return */
/* eslint-disable max-len */

// Imports
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
// const async = require('hbs/lib/async');
// const cookieParser = require('cookie-parser');
const { promisify } = require('util');
// const { request, response } = require('express');
const fetch = require('isomorphic-fetch');
const speakeasy = require('speakeasy');
const qrCode = require('qrcode');
const nodemailer = require('nodemailer');
// const { resolve } = require('path');
// const randtoken = require('rand-token');
// const expressValidator = require('express-validator');

// Store current email
let userEmail;

// Connect sql
const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE,
});

// Create OTP and transporter to send OTP email
let otp = 0;
let email;
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    service: 'Gmail',
    auth: {
        user: process.env.OTP_EMAIL,
        pass: process.env.OTP_PASS,
    },
});

// Generate OTP
function generateOTP() {
    let genotp;
    genotp = Math.random();
    genotp *= 100000;
    genotp = parseInt(genotp, 10);
    return genotp;
}

// Used to validate password against criteria, return true if no errors were found, otherwise return a message
function passwordValidation(password) {
    if (typeof password !== 'string') {
        return 'Invalid password';
    }

    const isWhitespace = /^(?=.*\s)/;
    if (isWhitespace.test(password)) {
        return 'Password must not contain Whitespaces.';
    }

    const isContainsUppercase = /^(?=.*[A-Z])/;
    if (!isContainsUppercase.test(password)) {
        return 'Password must have at least one Uppercase Character.';
    }

    const isContainsLowercase = /^(?=.*[a-z])/;
    if (!isContainsLowercase.test(password)) {
        return 'Password must have at least one Lowercase Character.';
    }

    const isContainsNumber = /^(?=.*[0-9])/;
    if (!isContainsNumber.test(password)) {
        return 'Password must contain at least one Digit.';
    }

    const isContainsSymbol = /^(?=.*[~`!@#$%^&*(){}\\[\]|\\"'<>,./_₹])/;
    if (!isContainsSymbol.test(password)) {
        return 'Password must contain at least one special character.';
    }

    const isValidLength = /^.{8,20}$/;
    if (!isValidLength.test(password)) {
        return 'Password must be 10-16 Characters Long.';
    }

    return true;
}

// Uses email param to generate an otp and send an email to the user trying to login
// returns an int depending on outcome
function sendOTP(email) {
    otp = generateOTP();
    const mailOptions = {
        to: email,
        subject: 'Your OTP to login',
        // eslint-disable-next-line no-useless-concat
        html: '<h3>OTP for account verification is </h3>' + `<h1 style='font-weight:bold;'>${otp}</h1>`,
    };

    transporter.sendMail(mailOptions, (error) => {
        if (error) {
            return 0;
        }
        return 1;
    });

    return null;
}

// Takes data from front-end, validates and encrypts it if needed and sends to the database
// Returns: message object to front end with different value depending on outcome
exports.register = (req, res) => {
    const {
        // eslint-disable-next-line no-shadow
        name, email, password, passwordConfirm,
    } = req.body;
    const message = passwordValidation(password);

    const responseKey = req.body['g-recaptcha-response'];
    const secretKey = process.env.CAPTCHA_SECRET;
    const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${responseKey}`;

    fetch(url, {
        method: 'post',
    })
        .then((response) => response.json())
        .then((googleResponse) => {
            if (googleResponse.success === true) {
            // sql query to find user using email, returns error and results to use as params in the nested function
            // note: '?', parameterized query helps against SQL injection
                db.query('SELECT email FROM users_test WHERE email = ?', [email], async (error, results) => {
                    if (error) {
                        console.log(error);
                    }

                    if (results.length > 0) {
                        return res.render('register.hbs', {
                            message: 'That email is already in use',
                            name,
                            email,
                        });
                    }
                    if (password !== passwordConfirm) {
                        return res.render('register.hbs', {
                            message: 'The passwords do not match',
                            name,
                            email,
                        });
                    }
                    if (!(/^[a-zA-Z]+$/.test(name)) || (typeof name !== 'string')) {
                        return res.render('register.hbs', {
                            message: 'Please enter only a first name and with only letters',
                            name,
                            email,
                        });
                    }

                    if (message !== true) {
                        return res.render('register.hbs', {
                            message,
                            name,
                            email,
                        });
                    }

                    // hash password
                    const hashedPassword = await bcrypt.hash(password, 8);

                    // send data to database
                    db.query('INSERT INTO users_test SET ? ', { name, email, password: hashedPassword }, (_error) => {
                        if (_error) {
                            console.log(error);
                        } else {
                            return res.render('register.hbs', {
                                successMessage: 'User Registered',
                            });
                        }
                    });
                });
            } else {
                return res.render('register.hbs', {
                    message: 'Failed Captcha.',
                    name,
                    email,
                });
            }
        })
        .catch((error) => res.json({ error }));
};

// Utility function to create delay
function delay(time) {
    return new Promise((resolve) => setTimeout(resolve, time));
}

// Validates user inputs and compares it with data in database to authenticate user,
// once logged in a cookie using web tokens is created to store the users data while the session is active.
// Returns: sends messages to front-end as well as user data if they manage to log in.
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const message = passwordValidation(password);

        if (!email || !password) {
            return res.status(400).render('login.hbs', {
                message: 'Please provide an email and password',
            });
        }

        // note: sends same message regardless of email failure or password failure or both
        db.query('SELECT * FROM users_test WHERE email = ?', [email], async (error, results) => {
            if (results < 1) {
                // equalize the server response times
                delay(20).then(() => res.status(401).render('login.hbs', { message: 'Email or password is incorrect' }));
                // res.status(401).render('login.hbs', {message: 'Email or password is incorrect'})
            } else if (message !== true) {
                res.status(401).render('login.hbs', { message: 'Email or password is invalid' });
            } else if (!(await bcrypt.compare(password, results[0].password))) {
                res.status(401).render('login.hbs', { message: 'Email or password is incorrect' });
            } else if (results[0].is_auth_verified === 1) {
                userEmail = email;
                res.render('auth-validate.hbs', { message: '' });
            } else if (results[0].is_email_otp_verified === 1) {
                userEmail = email;
                sendOTP(userEmail);
                res.render('email-otp-validate.hbs');
            } else {
                const { id } = results[0];
                const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES_IN,
                });
                const cookieOptions = {
                    expires: new Date(Date.now + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                    httpOnly: true,
                    secure: true,
                };
                res.cookie('jwt', token, cookieOptions);
                res.render('index.hbs', {
                    just_logged_in: true,
                    user: results[0],
                });
            }
        });
    } catch (error) {
        console.log(error);
    }
};

// Used whenever a page needs to know if the user is logged in or not,
// decodes web token data to find user and send data to front-end
exports.isLoggedIn = async (req, res, next) => {
    if (req.cookies.jwt) {
        try {
            // verify the token
            const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);

            // check is the user still exists
            db.query('SELECT * FROM users_test WHERE id = ?', [decoded.id], (error, result) => {
                if (!result) {
                    return next();
                }

                req.user = result[0];
                // currentUser = result[0];
                return next();
            });
        } catch (error) {
            console.log(error);
            return next();
        }
    } else next();
};

// Delete user cookie and redirects to home page
exports.logout = async (req, res) => {
    res.clearCookie('jwt');

    res.render('index.hbs', {
        just_logged_out: true,
    });
};

// Sets up the 2FA authentication system, generate a secret object using speakeasy,
// send the otpauth_url to the qrCode package to create a qr code image from it,
// update user record with new secret, reset user verification status to 0 (will be set to 1 when they verify the code in the next step)
// when successful re-render page, sending base32 code and data_url code to front-end to display QR
exports.setAuthenticator = (req, res) => {
    const secret = speakeasy.generateSecret();

    qrCode.toDataURL(secret.otpauth_url, (error, dataUrl) => {
        if (error) {
            console.log(error);
        } else {
            db.query(`UPDATE users_test SET ? WHERE id = ${req.user.id}`, {
                secret_ascii: secret.ascii, secret_hex: secret.hex, secret_base32: secret.base32, secret_otpauth_url: secret.otpauth_url, is_auth_verified: 0,
            }, (error) => {
                if (error) {
                    console.log(error);
                } else {
                    res.render('authenticator-setup.hbs', { code: secret.base32, dataUrl });
                }
            });
        }
    });
};

// Verify the token for the first time, so user record can be updated with authenticator verified status,
// from now on, whenever this user tries to log in they will be asked for the OTP from authenticator app
// use speakeasy to verify the code stored on database against token from app.
exports.verifyToken = (req, res) => {
    const userId = req.user.id;
    const { token } = req.body;

    db.query('SELECT * FROM users_test WHERE id = ?', [userId], (error, result) => {
        if (error) {
            console.log(error);
        } else {
            try {
                const user = result[0];
                const secret = user.secret_base32;

                const verified = speakeasy.totp.verify({
                    secret,
                    encoding: 'base32',
                    token,
                });

                if (verified) {
                    db.query(`UPDATE users_test SET ? WHERE id = ${req.user.id}`, { secret_base32: secret, is_auth_verified: 1, is_email_otp_verified: 0 });
                    res.render('authenticator-setup.hbs', { code: '', verify_success_msg: 'Successfully verified, you can now use the authenticator when logging in' });
                } else {
                    res.render('authenticator-setup.hbs', { code: '', verify_failed_msg: 'Verification failed, please get a new code.' });
                }
            } catch (e) {
                console.log(e);
                res.status(500).json({ message: 'Error finding user' });
            }
        }
    });
};

// Method used from now whenever user tries to login
exports.validateToken = (req, res) => {
    const { token } = req.body;

    db.query('SELECT * FROM users_test WHERE email = ?', [userEmail], (error, result) => {
        if (error) {
            console.log(error);
        } else {
            try {
                const user = result[0];
                const secret = user.secret_base32;

                // verifty token
                const verified = speakeasy.totp.verify({
                    secret,
                    encoding: 'base32',
                    token,
                    window: 1,
                });

                // if verified store session token and cookie data
                if (verified) {
                    const { id } = result[0];
                    const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                        expiresIn: process.env.JWT_EXPIRES_IN,
                    });
                    const cookieOptions = {
                        expires: new Date(Date.now + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                        httpOnly: true,
                    };
                    res.cookie('jwt', token, cookieOptions);

                    res.render('index.hbs', {
                        just_logged_in: true,
                        user: result[0],
                    });
                } else {
                    res.render('auth-validate.hbs', { message: 'Verification failed' });
                }
            } catch (e) {
                console.log(e);
                res.status(500).json({ message: 'Error finding user' });
            }
        }
    });
};

// Send an email through post router using sendOTPEmail() function, used when setting up
// Re-render page with success message
exports.sendOTPEmail = (req, res) => {
    email = req.user.email;

    sendOTP(email);
    res.render('email-otp-setup.hbs', {
        otp_sent_msg: 'Email has been sent successfully',
    });
};

// Verify email using OTP, update page with message and update database with statuses
// set authenticator status back to 0 so only email otp is activated now
exports.verifyEmailOTP = (req, res) => {
    // eslint-disable-next-line eqeqeq
    if (req.body.otp == otp) {
        res.render('email-otp-setup.hbs', {
            verify_success_msg: 'Successfully verified, you will now be sent an OTP when logging in',
        });

        db.query(`UPDATE users_test SET ? WHERE id = ${req.user.id}`, { is_email_otp_verified: 1, is_auth_verified: 0 });

        // generate new otp so same otp can't be used twice
        otp = generateOTP();
    } else {
        res.render('email-otp-setup.hbs', {
            verify_failed_msg: 'Incorrect code',
        });
    }
};

// Verify the OTP given by user against stored OTP and save cookie and jwt to login the user
exports.validateEmailOTP = (req, res) => {
    db.query('SELECT * FROM users_test WHERE email = ?', [userEmail], (error, result) => {
        if (error) {
            console.log(error);
        } else {
            try {
                const user = result[0];

                // eslint-disable-next-line eqeqeq
                if (req.body.otp == otp) {
                    const { id } = result[0];
                    const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                        expiresIn: process.env.JWT_EXPIRES_IN,
                    });
                    const cookieOptions = {
                        expires: new Date(Date.now + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                        httpOnly: true,
                    };
                    res.cookie('jwt', token, cookieOptions);

                    res.render('index.hbs', {
                        just_logged_in: true,
                        user,
                    });
                    // generate new otp so same otp can't be used twice
                    otp = generateOTP();
                } else {
                    res.render('email-otp-validate.hbs', { message: 'Verification failed' });
                }
            } catch (e) {
                console.log(e);
                res.status(500).json({ message: 'Error finding user' });
            }
        }
    });
};

// Reset users settings, used for activation indicator on profile page
exports.resetAuthSettings = (req, res) => {
    const userId = req.user.id;
    db.query(`UPDATE users_test SET ? WHERE id = ${userId}`, { is_auth_verified: 0 });
    res.render('profile.hbs', { reset_msg: 'Successfully reset your settings', user: req.user });
};
exports.resetOTPSettings = (req, res) => {
    const userId = req.user.id;
    db.query(`UPDATE users_test SET ? WHERE id = ${userId}`, { is_email_otp_verified: 0 });
    res.render('profile.hbs', { reset_msg: 'Successfully reset your settings', user: req.user });
};

// ============= PASSWORD RESET =============

// Create email and set mail options, then send when called
// eslint-disable-next-line no-unused-vars
function sendResetEmail(email, link) {
    const mail = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.OTP_EMAIL,
            pass: process.env.OTP_PASS,
        },
    });

    const mailOptions = {
        from: process.env.OTP_EMAIL,
        to: email,
        subject: 'Reset Password Link',
        html: `<p>You requested for reset password, kindly use this <a href=${link}>link</a> to reset your password, please note it will expire in <strong>30 minutes.</strong></p>`,

    };
    mail.sendMail(mailOptions);
}

// Create a jwt token using id and password, adding the password allows to make the token a one time use
function makeToken(id, password) {
    return jwt.sign({ id, password }, process.env.JWT_SECRET, { expiresIn: '30m' });
}

// Look for user from email input, if it exists make a token and link and send it,
// the same message is returned whether or not email is recognised
exports.sendResetLink = (req, res) => {
    email = req.body.email;

    db.query('SELECT * FROM users_test WHERE email = ?', [email], (error, results) => {
        if (error) {
            console.log(error);
            return;
        }
        if (results.length < 1) {
            res.render('forgot-password.hbs', { message: 'If that user exists a reset link will be sent via email' });
            return;
        }

        const user = results[0];
        const token = makeToken(user.id, user.password);

        const link = `http://localhost:5000/auth/reset-password/${user.id}?token=${token}`;
        console.log(link);
        // sendResetEmail(email, link)
        res.render('forgot-password.hbs', { message: 'If that user exists a reset link will be sent via email' });
    });
};

// The page that displays when user clicks the link, verifies the token first,
// redirects the user to home page if any failure scenario happens
exports.resetPasswordPage = (req, res) => {
    const { token } = req.query;
    const { id } = req.params;
    if (!token) {
        res.status(403);
        res.redirect('/');
        return;
    }
    db.query('SELECT * FROM users_test WHERE id = ?', [id], (error, results) => {
        if (error) {
            console.log(error);
        }
        const user = results[0];

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            res.status(403);
            res.redirect('/');
            return;
        }

        // check the decoded password with the user's current password, if it doesn't match then user is redirected,
        // because this means they have already reset their password with this link
        if (decoded.password !== user.password) {
            return res.redirect('/');
        }

        res.render('reset-password.hbs', { id: decoded.id });
    });
};

// Post method to update user record with new hashed password
exports.resetPassword = async (req, res) => {
    const userId = req.params.id;
    const newPassword = req.body.password;
    const newPassword2 = req.body.password2;
    const message = passwordValidation(newPassword);

    // check if passwords match
    if (newPassword !== newPassword2) {
        return res.render('reset-password.hbs', { message: 'Passwords do not match', id: userId });
    }
    // check if password passes validation
    if (message !== true) {
        return res.render('reset-password.hbs', { message, id: userId });
    }

    // hash and update database, this time re-render page with a message,
    // without passing userid so they can't reset password again straight away
    const hashedPassword = await bcrypt.hash(newPassword, 8);
    db.query(`UPDATE users_test SET ? WHERE id = ${userId}`, { password: hashedPassword });
    res.render('reset-password.hbs', { success_message: 'Password successfully reset' });
};

// When not passing userId the website will redirect to /auth/reset-password,
// with the missing ID, the page will just re-render with the appropriate message
exports.passResetError = (req, res) => {
    res.render('reset-password.hbs', { message: 'You have already reset your password, please login, or request another link' });
};
