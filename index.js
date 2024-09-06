require('dotenv').config(); // For environment variables

const express = require('express');
const app = express();
const User = require('./models/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');

const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'shhhhh';

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.render("signup");
});

app.post('/signup', async (req, res) => {
    const { firstName, lastName, username, email, password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        return res.render('signup', {
            message: "Passwords do not match.",
            firstName,
            lastName,
            username,
            email
        });
    }
    try {
        const existingUser = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existingUser) {
            return res.render('signup', {
                message: "Username or email already exists. Please login.",
                firstName,
                lastName,
                username,
                email
            });
        }

        const hash = await bcrypt.hash(password, 10);
        
        const user = await User.create({
            firstName,
            lastName,
            username,
            email,
            password: hash
        });

        // Using user id in JWT payload for clarity
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/profile');
    } catch (err) {
        console.error(err);
        res.status(500).send('An error occurred during signup.');
    }
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/login', async (req, res) => {
    const { identifier, password } = req.body;
    try {
        const user = await User.findOne({
            $or: [{ email: identifier }, { username: identifier }]
        });
        if (!user) {
            return res.status(404).render('login', { message: 'User not found.' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).render('login', { message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/profile');
    } catch (err) {
        console.error(err);
        res.status(500).send('An error occurred during login.');
    }
});

app.get('/profile', isLoggedIn, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).send('User not found');
        }

        res.render('profile', { user });
    } catch (err) {
        console.error(err);
        res.status(500).send('An error occurred while fetching the profile');
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

// Middleware for authentication
function isLoggedIn(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;  // attach decoded user data to the request
        next();
    } catch (err) {
        console.error(err);
        res.clearCookie('token');
        res.redirect('/login');
    }
}

app.listen(PORT, () => console.log(`Server is running on port ${PORT}.`));
