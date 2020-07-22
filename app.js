//jshint esversion:6
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const app = express();
// const encrypt = require('mongoose-encryption');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')


app.use(express.static('public'));
app.set('view engine','ejs')
app.use(bodyParser.urlencoded({extended:true}));


app.use(session({
    secret:'Our little secret',
    resave:false,
    saveUninitialized:false,
}))
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb+srv://admin-jatin:'+process.env.mongoconnetPassword+'@cluster0.ktbyq.mongodb.net/userDB', {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    username:String,
    password:String,
    googleId:String,
    facebookId:String,
    secrets:[String],
})
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]})
const User = mongoose.model('User',userSchema);

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
    callbackURL: "https://limitless-sands-18547.herokuapp.com/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://limitless-sands-18547.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
let isLogin = false;
app.route('/')
.get((req,res)=>{
    res.render('home');
})
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    isLogin=true;
    res.redirect('/secrets');
  });


app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    isLogin=true;
    res.redirect('/secrets');
  });


app.route('/login')
.get((req,res)=>{
    res.render('login');
})
.post((req,res)=>{
    const {username,password} = req.body;
    const user = new User({
        username,password
    })
    req.login(user,function(err){
        if(err) {console.log(err);
            res.redirect('/register')}
        else{
            passport.authenticate("local")(req,res,function(err){
                if(err)
                {
                  console.log(err);
                }
                else{
                  isLogin=true;
                res.redirect('/secrets');
                }
             })   
        }
    })
})
app.route('/logout')
.get((req,res)=>{
    req.logout();
    isLogin=false;
    res.redirect('/');
})
app.route('/secrets')
.get((req,res) =>{
    
    User.find({"secrets":{$ne:null}},(err,foundUser)=>{
     if(err) console.log(err);
     else{
      if(foundUser)
      {
        res.render('secrets',{userHaveSecrets :foundUser,isLogin});
      }  
     }
    })
 

})

app.route('/register')
.get((req,res)=>{
    res.render('register',{userExist:false});
})
.post((req,res)=>{
    let userExist = false;
    const {username,password} = req.body;
    User.find({username},(err,user)=>{
      if(err)
      {
        console.log(err);
      }
      else{
        if(user.length!==0)
        {
          res.render('register',{userExist:true});
        }
        else{
           userExist=true;
           User.register({username},password,(err,user)=>{
            if(err)
            {
                console.log(err);
                res.redirect('/register')
            }
            else{
                passport.authenticate("local")(req,res,function(){
                   isLogin=true;
                   res.redirect('/secrets');
                })
            }
        })
        }
      }
    })
   
})

app.get('/submit',(req,res)=>{
    if(req.isAuthenticated())
    {
      res.render('submit');
    }
    else{
      res.redirect('/login');
    }
})
app.post('/submit',(req,res)=>{
  User.updateOne(
    { _id: req.user.id },
    { $push: { secrets: req.body.secret }},
    (err)=>{
      err?console.log(err):res.redirect('/secrets');
    }
 )
})
app.get('/about',(req,res)=>{
  res.render('about',{isLogin});
})
app.get('/contact',(req,res)=>{
  res.render('contact',{isLogin});
})
app.get('/profile',(req,res)=>{
  if(req.isAuthenticated())
  {
    User.findById(req.user.id,(err,User)=>{
      if(!err)
      {
        res.render('profile',{secrets:User.secrets});
      }
    })
  }
  else{
    res.redirect('/login');
  }
})
app.post('/delete',(req,res)=>{
  User.updateOne(
    { _id: req.user.id },
    { $pull: { secrets: req.body.toBeDelete }},
    (err)=>{
      err?console.log(err):res.redirect('/profile');
    }
 )
})
app.listen((process.env.PORT || 3000),()=>{
    console.log('server running on port 3000');
})