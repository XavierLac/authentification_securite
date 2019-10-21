// Quand le code est modifié et sauvegardé, nodemon redémarre le serveur, les cookies sont supprimés et la session détruite.
//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(
  bodyParser.urlencoded({
    extended: true
  })
);

// On dit à l'application d'utiliser le package session avec la configuration renseignée
app.use(
  session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
  })
);

// On dit à l'application d'utiliser et d'initialiser le package Passport
app.use(passport.initialize());
// On dit à l'application d'utiliser Passport pour gérer le package session
app.use(passport.session());

const options = {
  useUnifiedTopology: true,
  useNewUrlParser: true
};

// 27017 = port par défaut de mongodb
mongoose.connect('mongodb://localhost:27017/userDB', options);
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model('User', userSchema);

// Passport
// Serialize => Passport crée un cookie et y stocke les données de l'internaute
// Deserialize => Passport ouvre le cookie et découvre les informations qu'il contient, autrement dit qui est l'internaute

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get('/secrets', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('secrets');
  } else {
    res.redirect('/login');
  }
});

app.get('/logout', (req, res) => {
  req.logOut();
  res.redirect('/');
});

app.post('/register', function(req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.redirect('/register');
      } else {
        passport.authenticate('local')(req, res, () => {
          res.redirect('/secrets');
        });
      }
    }
  );
});

app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, err => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, () => {
        res.redirect('/secrets');
      });
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
