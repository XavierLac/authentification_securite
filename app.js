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
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

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
  password: String,
  googleId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

// Passport
// Serialize => Passport crée un cookie et y stocke les données de l'internaute
// Deserialize => Passport ouvre le cookie et découvre les informations qu'il contient, autrement dit qui est l'internaute

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
      // userProfileURL est ajouté pour récupérer les informations depuis le endpoint userinfo et non plus Google+ (le service est désormais fermé et donc inutilisable)
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
    },
    function(accessToken, refreshToken, profile, cb) {
      // findOrCreate n'est pas une vraie fonction. La personne qui a rédigé la document de la stratégie Passport pour GoogleOAuth2 conseille d'utiliser une méthode find or create d'où le nom. Néanmoins, d'autres développeurs ont codé une fonctionnalité basée sur ce nom et utilisable via le package npm i mongoose-findorcreate
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function(err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get('/', (req, res) => {
  res.render('home');
});

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get(
  '/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  }
);

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
