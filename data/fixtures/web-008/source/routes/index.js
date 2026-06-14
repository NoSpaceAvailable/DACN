var express = require('express');
var router = express.Router();
var crypto = require("crypto");
var db = require('../database');

function restrict(req, res, next) {
  if (req.session.user) next();
  else { req.session.error = 'Access denied!'; res.redirect('/'); }
}

function trim_whitespace(input_str) {
  var trimmed = input_str;
  const regex = /[ %]/;
  var bad_chr_ind = trimmed.search(regex);
  if (bad_chr_ind != -1) {
    trimmed = trimmed.slice(0, bad_chr_ind);
  }
  return trimmed;
}

function authenticate(name, pass, fn) {
  hash = crypto.createHash('sha256').update(pass).digest('hex');
  var qry = `SELECT rowid FROM users WHERE uname = '${name}' AND pass = '${hash}'`;
  db.get(qry, [], (err, row) => {
    return fn(null, row);
  });
}

router.get('/', function(req, res) {
  if (req.session.error) req.session.error = "";
  if (req.session.username) req.session.username = "";
  res.redirect('/login');
});

router.get('/home', restrict, function(req, res) {
  res.render('index', { title: 'Super Secure Section' });
});

router.get('/login', function(req, res) {
  var auth_error = req.session.error;
  var username = req.session.username;
  res.render('login', {"error": auth_error, "username": username});
});

router.post('/login', function(req, res) {
  var username = trim_whitespace(req.body.username);
  var password = trim_whitespace(req.body.password);
  username = username.replace('admin', '');
  req.session.username = username;

  authenticate(username, password, function(err, user) {
    if (user) {
      req.session.regenerate(function() {
        req.session.user = user['rowid'];
        req.session.success = 'Authenticated as ' + req.session.user;
        res.redirect('/home');
      });
    } else {
      req.session.error = "Authentication failed.";
      res.redirect('/login');
    }
  });
});

module.exports = router;
