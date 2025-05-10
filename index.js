require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const Joi = require("joi");
const app = express();

app.set("view engine", "ejs");

const expireTime = 1 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

const port = process.env.PORT || 3000;

// MongoDB connection details
const MONGODB_HOST = process.env.MONGODB_HOST;
const MONGODB_USER = process.env.MONGODB_USER;
const MONGODB_PASSWORD = process.env.MONGODB_PASSWORD;
const MONGODB_SESSION_SECRET = process.env.MONGODB_SESSION_SECRET;
const MONGODB_DATABASE = process.env.MONGODB_DATABASE;

const NODE_SESSION_SECRET = process.env.NODE_SESSION_SECRET;

var { database } = require("./databaseConnection");
const usersCollection = database.db(MONGODB_DATABASE).collection("users");

app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));

// creates sessoins database in MongoDB to store sessions
// and uses the session secret to encrypt the session data
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${MONGODB_USER}:${MONGODB_PASSWORD}@${MONGODB_HOST}/assignment1`,
  crypto: {
    secret: MONGODB_SESSION_SECRET,
  },
});

app.use(
  session({
    secret: NODE_SESSION_SECRET,
    store: mongoStore, // store session data in MongoDB
    saveUninitialized: false,
    resave: true,
  })
);

// Middleware functions
function auth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function adminOnly(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  if (req.session.user.user_type !== 'admin') {
    return res.status(404).render('404', { user: req.session.user, message: 'Access denied. Admins only.' });
  }
  next();
}

// Routes

// Home Page
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Sign Up Page
app.get('/signup', (req, res) => {
  res.render('signup', { error: null, user: req.session.user });
});

app.post('/signup', async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).render('signup', { error: 'All fields are required and must be valid.', user: null });
  }

  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const newUser = {
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
    user_type: 'user'
  };

  await usersCollection.insertOne(newUser);
  req.session.user = {
  name: newUser.username,
  email: newUser.email,
  user_type: newUser.user_type
};

  res.redirect('/members');
});

// Log In Page
app.get('/login', (req, res) => {
  res.render('login', { error: null, user: req.session.user });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await usersCollection.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).render('login', { error: 'Invalid email or password.', user: null });
  }

  req.session.user = {
  name: user.username,
  email: user.email,
  user_type: user.user_type
};

  res.redirect('/members');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Members Page (Authorized)
app.get('/members', auth, (req, res) => {
  const images = ['golestan.jpg', 'isfahan.jpg', 'mosque.jpg'];
  res.render('members', { user: req.session.user, images });
});

// Admin Page (Admins Only)
app.get('/admin', adminOnly, async (req, res) => {
  const users = await usersCollection.find().toArray();
  res.render('admin', { user: req.session.user, users });
});

// Promote User to Admin
app.get('/promote/:email', adminOnly, async (req, res) => {
  await usersCollection.updateOne({ email: req.params.email }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
});

// Demote Admin to User
app.get('/demote/:email', adminOnly, async (req, res) => {
  await usersCollection.updateOne({ email: req.params.email }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
});

// 404 Page (Catch-all)
app.use((req, res) => {
  res.status(404).render('404', { user: req.session.user, url: req.originalUrl, message: 'Page not found.' });
});

// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
