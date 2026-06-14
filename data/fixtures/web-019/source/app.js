const express = require('express');
const app = express();
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bodyParser = require("body-parser");
const router = express.Router();
const path = __dirname + '/views/';
const port = 3010;

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.urlencoded({extended: false}));

app.use(session({ secret: "secret", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy((user, password, done) => {
    if (user.toString().toLowerCase().trim() === "nginx" && password.toString().toLowerCase().trim() === '1.17.6') {
        return done(null, { id: 123, name: "nginx" });
    }
    return done(null, false);
}));
passport.serializeUser((u, done) => done(null, u.id));
passport.deserializeUser((id, done) => done(null, {name: "zoidberg", id: 123}));

app.get("/hint", (req, res) => res.render("hint.ejs"));
app.post("/hint", passport.authenticate('local', {
    successRedirect: "/succeed_hint",
    failureRedirect: "/hint",
}));
app.get("/succeed_hint", (req, res) => {
    if (req.isAuthenticated()) return res.render("succeed_hint.ejs");
    res.redirect("/hint");
});

router.get("/", (req, res) => res.render("index"));
app.use(express.static(path));
app.use('/', router);

var server = app.listen(port, 'localhost', function () {});
server.keepAliveTimeout = 30000;
