const express = require('express');
const router = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('../models/user');

// Register
router.get('/register', function (req, res) {
	res.render('register');
});

// Login
router.get('/login', function (req, res) {
	res.render('login');
});

// Register User
router.post('/register', function (req, res) {
	let name = req.body.name;
	let email = req.body.email;
	let username = req.body.username;
	let address = req.body.address;
	let phonenumber = req.body.phonenumber;
	let password = req.body.password;
	let password2 = req.body.password2;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	if (email !== "") {
		req.checkBody('email', 'Email is not valid').isEmail();
	}
	
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('address', 'Address is required').notEmpty();
  req.checkBody('phonenumber','phonenumber is required').notEmpty();
  req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	let errors = req.validationErrors();

	if (errors) {
		res.render('register', {
			errors: errors
		});
	}
	else {
		//checking for email and username are already taken
		User.findOne({ username: { 
			"$regex": "^" + username + "\\b", "$options": "i"
	}},(err, user) => {
			User.findOne({ email: { 
				"$regex": "^" + email + "\\b", "$options": "i"
		}},(err, mail) => {
				if (user || mail) {
					res.render('register', {
						user: user,
						mail: mail
					});
				}
				else {
					let newUser = new User({
						name: name,
						email: email,
						username: username,
						address:address,
						phonenumber:phonenumber,
						password: password
					});

					console.log(newUser,"newUser");
					User.createUser(newUser,(err, user) => {
						if (err) throw err;
						console.log(user);
					});
         	req.flash('success_msg', 'You are registered and can now login');
					res.redirect('/users/login');
				}
			});
		});
	}
});

passport.use(new LocalStrategy(
	(username, password, done) => {
		User.getUserByUsername(username,(err, user) => {
			if (err) throw err;
			if (!user) {
				return done(null, false, { message: 'Unknown User' });
			}

			User.comparePassword(password, user.password, (err, isMatch) => {
				if (err) throw err;
				if (isMatch) {
					return done(null, user);
				} else {
					return done(null, false, { message: 'Invalid password' });
				}
			});
		});
	}));

passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser((id, done) => {
	User.getUserById(id,(err, user) => {
		done(err, user);
	});
});

router.post('/login',
	passport.authenticate('local', 
		{ successRedirect: '/', 
		  failureRedirect: '/users/login', 
		  failureFlash: true 
	  }),
	(req, res) => {
        res.redirect('/');
	});

router.get('/logout',(req, res) => {
	req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
});


module.exports = router;