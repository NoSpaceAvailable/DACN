const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const expressValidator = require("express-validator");
const session = require("express-session");
require("dotenv").config();

const app = express();

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

const User = mongoose.model("User", userSchema);

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(expressValidator());

app.get("/", async (req, res) => {
  res.sendFile(__dirname + "/app.js");
});

app.post("/register", async (req, res) => {
  let { username, password } = req.body;
  req.checkBody("username", "Invalid username").notEmpty();
  req.checkBody("password", "Invalid password").notEmpty();
  const errors = req.validationErrors();
  if (errors) return res.status(400).json({ errors });
  username = username.toLowerCase();
  if (username === "ram") {
    return res.status(400).json({ error: "using my tricks against me, huh?" });
  }
  const user = await User.findOne({ username });
  if (user) return res.status(400).json({ error: "user already exists" });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "Registration successful" });
  } catch {
    res.status(201).json({ message: "Something went wrong" });
  }
});

app.post("/login", async (req, res) => {
  let { username, password } = req.body;
  req.checkBody("username", "Invalid username").notEmpty();
  req.checkBody("password", "Invalid password").notEmpty();
  const errors = req.validationErrors();
  if (errors) return res.status(400).json({ errors });
  username = username.toLowerCase();
  if (username === "ram") {
    return res.status(400).json({ error: "using my tricks against me, huh?" });
  }
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  bcrypt.compare(password, user.password, (bcryptErr, isMatch) => {
    if (bcryptErr) return res.status(500).json({ error: "Internal server error" });
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });
    req.session.userId = user._id;
    req.session.username = user.username;
    res.json({ message: "Login successful, go to /profile/<your_username>" });
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Logged out" });
});

app.get("/profile/:profile", (req, res) => {
  req.params.profile = req.params.profile.toLowerCase();
  if (!req.session.userId) {
    return res.status(403).json({ error: "Unauthorized" });
  } else if (req.params.profile === "ram") {
    return res.status(200).send(process.env.FLAG);
  } else if (req.session.username !== req.params.profile) {
    return res.status(401).json({ error: "haha, trying to be smart?" });
  }
  res.json({
    message: "Oh, did you miss anything?",
    user: req.session.userId,
  });
});

app.listen(4999, () => {
  console.log("Server is running on port 4999");
});
