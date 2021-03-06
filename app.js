// Imports
const express = require('express');
const helmet = require('helmet');
// eslint-disable-next-line no-unused-vars
const dotenv = require('dotenv').config();
const mysql = require('mysql');
const path = require('path');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const methodOverride = require('method-override');
// const Article = require('./models/Article');
const articleRouter = require('./routes/articles');

const app = express();

// Create connection to SQL database using data stored in .env file
const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE,
});

// Connect to mongoDB database
mongoose.connect('mongodb+srv://win20:201099@cluster0.cvtiy.mongodb.net/blog-posts?retryWrites=true&w=majority', {
    useNewUrlParser: true,
});

app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            'script-src': ["'self'", 'https://www.google.com/recaptcha/', 
            'https://www.gstatic.com/recaptcha/', 
            'https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
        ],
            'frame-src': ["'self'", 'https://www.google.com/recaptcha/', 
            'https://www.gstatic.com/recaptcha/', 
            'https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
        ],
        },
    },
}));

// Set /public directory to server static resources (images, scripts, css)
const publicDirectory = path.join(__dirname, './public');
app.use(express.static(publicDirectory));

// Parse URL encoded bodies, grab data from form
app.use(express.urlencoded({ extended: false }));
// Parse JSON bodies, values from form come in as JSON
app.use(express.json());
app.use(cookieParser());

// Set view engines
app.set('view engine', 'hbs');
app.set('view engine', 'ejs');

// Override method to use in form actions
app.use(methodOverride('_method'));

// Send message depending on outcome of connection attempt to mySQL
db.connect((error) => {
    if (error) {
        console.log(error);
    } else {
        console.log('MYSQL Connected...');
    }
});

// Define routes
app.use('/', require('./routes/pages'));
app.use('/auth', require('./routes/auth'));

app.use('/articles', articleRouter);

// Start server on
app.listen(5000, () => {
    console.log('Server started on port 5000');
});
