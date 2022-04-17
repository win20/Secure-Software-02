# Secure-Software-02 - Gym Rat | Fitness Blog

This project showcases authentication systems as well as methods to secure a web app against common security threats,
it is themed as a fitness blog however the web design/development aspect is not the main aim as opposed to the security side.

## Prerequisites

Since the project is not going to be on an online server we need to start a local server:
- XAMPP: Used to start a local server, needs to be downloaded onto device.
- Command Prompt: Used to connect to server.

## How to run the project

1. Open XAMPP and start the Apache and mySQL servers.
2. Open the command prompt ('cmd').
3. Navigate to the project folder by using the 'cd' command, eg: **cd C:\path\to\file\Secure-Software-02**.
4. Connect to the server, type: **npm start**. This should tell you the port of the server and confirm the mySQL connection as shown:

  ![Screenshot of results](https://github.com/win20/Secure-Software-02/blob/main/git-imgs/cmd-connect.PNG)

5. Now go to your browser and in the url bar type: **http://localhost:5000/**, the '5000' can be changed to any port that you are listening to but it is 5000 by default.
6. This should take you to the website.

## Main Libraries & Frameworks
- [Bootstrap](https://getbootstrap.com/) - Framework that allows quicker creation of clean and responsive websites. Used for frontend.
- [Node.js v16.14.2](https://nodejs.org/en/) - Server-side language used for all the backend code, based on JavaScript.
- [Express.js](https://expressjs.com/) - The standard library used alongside Node.js.
- [JWT](https://jwt.io/) - For creating web tokens, used alongside cookies.
- [Bcryptjs](https://www.npmjs.com/package/bcryptjs) - Allows us to salt and hash passwords, as well as comparing using **timing safe** methods.
- [Dotenv](https://www.npmjs.com/package/dotenv) - Stores environment variables securely.
- [Handlebars.js](https://www.npmjs.com/package/handlebars) - Web templating system, contains all the HTML code and allows conditional markdown.


## Contributors

- Win Barua - qnk19zxu
- Simon Newton - aaaaaaa

## References & credits
1. [JWT Documentation](https://jwt.io/introduction)
2. [Node.js Documentation](https://nodejs.org/dist/latest-v16.x/docs/api/)
3. [Express.js Documentation](https://devdocs.io/express/)
4. [CodeShack - Basic login system](https://codeshack.io/basic-login-system-nodejs-express-mysql/)
5. [NiceSnippets.com - Node.js and Express.js login with mySQL example](https://www.nicesnippets.com/blog/nodejs-express-login-with-mysql-example)
6. [Section.io - Understanding cookies and implementing them in Node.js](https://www.section.io/engineering-education/what-are-cookies-nodejs/)
7. [GeeksforGeeks.com - HTTP cookies in Node.js](https://www.geeksforgeeks.org/http-cookies-in-node-js/)
8. [Youtube - Build a Node.js Authentication with JWT Tutorial](https://www.youtube.com/watch?v=2jqok-WgelI&t=2941s&ab_channel=DevEd)
9. [Youtube - Node.js Register & Login Tutorial - Learn how to authenticate with Node.js, MongoDB and JWT](https://www.youtube.com/watch?v=b91XgdyX-SM&t=343s&ab_channel=codedamn)

*Note: Tutorials were followed only as guidelines and so we could learn the basics of how the libraries work and ideas on how to elegantly stitch them together, the creation of the system as a whole required us to take things from each tutorial and documentations and combine them as well as add our own code from scratch for most of the project.*
