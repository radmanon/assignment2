require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

app.set("view engine", "ejs");

const Joi = require("joi");
// For login
const loginSchema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().required()
});

// For signup (including an email validation)
const signupSchema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const expireTime = 60 * 60 * 1000; // 1 hour in milliseconds

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore, // using MongoDB to store session
    saveUninitialized: false,
    resave: false, // to avoid unnecessary session saving
    cookie: {
        maxAge: expireTime // set the session expiration from configuration
    }
}));

app.get('/', (req, res) => {
    res.render('index', { title: 'Home', authenticated: req.session.authenticated, username: req.session.username });
});

app.get('/members', (req, res) => {
    if (req.session.authenticated) {
        const images = ['/img1.png', '/img2.png', '/img3.png'];
        res.render('members', {
            title: 'Members',
            authenticated: req.session.authenticated,
            username: req.session.username,
            images: images
        });
    } else {
        res.redirect('/login');
    }
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>No user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.send("<h1 style='color:" + color + ";'>Patrick Guichon</h1>");
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        Email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> Email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});

app.get('/signup', (req, res) => {
    res.render('signup', { title: 'Signup', authenticated: req.session.authenticated, error: null });
});

app.get('/login', (req, res) => {
    res.render('login', { title: 'Login', error: req.query.error, authenticated: req.session.authenticated });
});

app.get('/admin', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        const user = await userCollection.findOne({ username: req.session.username });
        if (user && user.user_type === 'admin') {
            const users = await userCollection.find().toArray();
            res.render('admin', {
                title: 'Admin',
                users: users,
                authenticated: req.session.authenticated // Pass authenticated status
            });
        } else {
            res.status(403).send('<h1>403 - Forbidden</h1><p>You are not authorized to view this page.</p>');
        }
    }
});


app.post('/submitUser', async (req, res) => {
    try {
        var username = req.body.username;
        var email = req.body.email;
        var password = req.body.password;

        const schema = Joi.object({
            username: Joi.string().alphanum().min(3).max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().min(6).max(20).required()
        });

        const validationResult = schema.validate({ username, email, password });
        if (validationResult.error != null) {
            const errors = validationResult.error.details.map(detail => detail.message).join(', ');
            console.log(validationResult.error);
            res.render('signup', { title: 'Signup', authenticated: req.session.authenticated, error: errors });
            return;
        }

        var hashedPassword = await bcrypt.hash(password, saltRounds);
        await userCollection.insertOne({ username: username, email: email, password: hashedPassword, user_type: 'user' });
        console.log("Inserted user");

        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        // Redirect to the members page after successful signup
        res.redirect('/members');
    } catch (error) {
        console.error(error);
        res.render('signup', { title: 'Signup', authenticated: req.session.authenticated, error: 'An error occurred during signup.' });
    }
});


app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login?error=1");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, _id: 0 }).toArray();

    if (result.length != 1 || !(await bcrypt.compare(password, result[0].password))) {
        console.log("Authentication failed");
        res.redirect("/login?error=1");
        return;
    }

    console.log("Correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/');
});

app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        var html = `
        You are logged in! Hello, ${req.session.username}
        `;
        res.send(html);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log('Error destroying session:', err);
            res.status(500).send('An error occurred while logging out.');
        } else {
            // Clear the cookie to ensure session is completely removed
            res.clearCookie('connect.sid', { path: '/' });
            res.redirect('/');
        }
    });
});

app.get('/cat/:id', (req, res) => {
    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    } else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    } else {
        res.send("Invalid cat id: " + cat);
    }
});


app.get('/promote/:username', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        const user = await userCollection.findOne({ username: req.session.username });
        if (user && user.user_type === 'admin') {
            await userCollection.updateOne(
                { username: req.params.username },
                { $set: { user_type: 'admin' } }
            );
            res.redirect('/admin');
        } else {
            res.status(403).send('<h1>403 - Forbidden</h1><p>You are not authorized to perform this action.</p>');
        }
    }
});

app.get('/demote/:username', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        const user = await userCollection.findOne({ username: req.session.username });
        if (user && user.user_type === 'admin') {
            await userCollection.updateOne(
                { username: req.params.username },
                { $set: { user_type: 'user' } }
            );
            res.redirect('/admin');
        } else {
            res.status(403).send('<h1>403 - Forbidden</h1><p>You are not authorized to perform this action.</p>');
        }
    }
});


app.use(express.static(__dirname + "/public"));

// Ensure 404 handling after all routes
app.get('*', (req, res) => {
    res.status(404).render('404', { title: '404', authenticated: req.session.authenticated });
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});