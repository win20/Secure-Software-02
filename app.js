// Imports
const express = require('express');
const mysql = require('mysql');
const dotenv = require('dotenv').config();
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();

// Connect to mySQL database
const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});


const publicDirectory = path.join(__dirname, './public');
app.use(express.static(publicDirectory));

// Parse URL encoded bodies, grab data from form
app.use(express.urlencoded({ extended: false }));
// Parse JSON bodies, values from form come in as JSON
app.use(express.json());
app.use(cookieParser());

app.set('view engine', 'hbs');

db.connect( (error) => {
    if(error) {
        console.log(error);
    } else {
        console.log('MYSQL Connected...')
    }
})

// Define routes
app.use('/', require('./routes/pages'));
app.use('/auth', require('./routes/auth'));

app.listen(5000, () => {
    console.log('Server started on port 5000');
});