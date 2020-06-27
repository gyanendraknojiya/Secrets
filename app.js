//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
mongoose.set('useCreateIndex', true);
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    profile_name: String,
    secret: String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "https://gyanendra3.herokuapp.com/auth/google/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {

        User.findOrCreate({ googleId: profile.id, profile_name: profile.displayName }, function(err, user) {
            return cb(err, user);
        });
    }
));
passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "https://gyanendra3.herokuapp.com/auth/facebook/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {

        User.findOrCreate({ facebookId: profile.id, profile_name: profile.displayName }, function(err, user) {
            return cb(err, user);
        });
    }
));


app.get('/', function(req, res) {
    res.render('home');
});
app.get('/login', function(req, res) {
    res.render('login');
});
app.get('/register', function(req, res) {
    res.render('register');
});
app.get('/secrets', function(req, res) {
    User.find({ secret: { $ne: null } }, function(err, userSecret) {
        if (err) {
            console.log(err);
        } else {
            res.render('secrets', { userWithSecret: userSecret });
        }
    });

});
app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

app.get('/submit', function(req, res) {
    if (req.isAuthenticated()) {
        res.render('submit');
    } else {
        res.redirect('/login');
    }
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

app.post('/register', function(req, res) {
    User.findOne({ username: req.body.username }, function(err, result) {
        if (!result) {
            User.register({ username: req.body.username }, req.body.password, function(err, user) {
                if (err) {
                    res.redirect('/register');
                } else {
                    passport.authenticate('local')(req, res, function() {
                        res.redirect('/secrets');
                    });
                }
            });
        } else {
            res.send('Account already exists');
        }
    });

});

app.post('/login', function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err) {
        if (err) {
            res.redirect('/login');
        }
        return res.redirect('/secrets');
    });

});

app.post('/submit', function(req, res) {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            foundUser.secret = submittedSecret;
            foundUser.save();
            res.redirect('/secrets');
        }
    });
});



 


app.listen(process.env.PORT, function() {
    console.log('server is running at port' + process.env.PORT);
});