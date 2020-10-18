//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true
  // cookie: {
  //   secure: true
  // }
}));

// initialize the passport package
app.use(passport.initialize());
// use passport for dealing with the sessions
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/secretDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
  useCreateIndex: true
});

// object created from mongoose Schema class
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
// serializeUser and deserializeUser - it is only nessesary when we use session.
// serializeUser & deserializeUser it is from passport-local-mongoose package and it is only for local strategy authentication.
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// this serializeUser and deserializeUser used for all cases authentication.
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// this piece of code is need to be right here before all routs and after session and passport require
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log("Google Id: " + profile.id);
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log("Facebook Id: " + profile.id);
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/google",
  /* "scope: ['profile']" - we want the user's profile and this includes user's email
  and user ID on Google which we'll be able to use and identify users in the future.*/
  passport.authenticate('google', {
    scope: ['profile']
  }));

app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect secret.
    res.redirect("/secrets");
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  // login() - is function from passport
  req.login(user, (err) => {
    if (err)
      console.log(err);
    else {
      // here callback function () is triggered only if user pass the authentication
      passport.authenticate('local')(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  // register - is passport-local-mongoose method
  User.register({
    username: req.body.username
  }, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      // here callback function () is triggered only if user pass the authentication
      // local authentication of user.
      passport.authenticate('local')(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/secrets", (req, res) => {
  User.find({
    "secret": {
      $ne: null
    }
  }, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {
          usersWithSecrets: foundUsers
        });
      }
    }
  });
});

app.get("/submit", (req, res) => {
  // console.log(req.isAuthenticated());
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;
  /* passport saves the users details because when we initiate a new login session
  it will say that users details into the request variable.*/
  console.log(req.user.id);
  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        /* we can use empty callback function to go to the next step.
        It is promises to us that firstly we save the user and after
        that we redirect to the "secret" route*/
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", (req, res) => {
  //  logout if function from passport
  req.logout();
  res.redirect("/");
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
