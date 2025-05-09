require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const Joi = require("joi");
const app = express();

const expireTime = 1 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

const PORT = process.env.PORT || 3000;

// MongoDB connection details
const MONGODB_HOST = process.env.MONGODB_HOST;
const MONGODB_USER = process.env.MONGODB_USER;
const MONGODB_PASSWORD = process.env.MONGODB_PASSWORD;
const MONGODB_SESSION_SECRET = process.env.MONGODB_SESSION_SECRET;
const MONGODB_DATABASE = process.env.MONGODB_DATABASE;

const NODE_SESSION_SECRET = process.env.NODE_SESSION_SECRET;

var { database } = require("./databaseConnection");
const userCollection = database.db(MONGODB_DATABASE).collection("users");

app.use(express.urlencoded({ extended: true }));

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

// Routes
app.get("/", (req, res) => {
  if (req.session.authenticated) {
    var html = `
        <h1>Welcome to the website ${req.session.username}!</h1>
        <button><a href="/members">Go to members area</a></button>
        <button><a href="/logout">Logout</a></button>
        `;
  } else {
    var html = `
        <h1>Welcome to the website!</h1>
        <button><a href="/signup">Signup</a></button>
        <button><a href="/login">Login</a></button>
        `;
  }
  res.send(html);
});

app.get("/signup", (req, res) => {
  var html = `
    <h1>Welcome to the signup page!</h1>
    <form action="/signupSubmit" method="POST">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="email">Email:</label><br>
        <input type="email" id="email" name="email"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Submit">
    </form>
    `;
  res.send(html);
});

app.post("/signupSubmit", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;
  var username = req.body.username;

  var html = `<p>`;

  console.log(`Name: ${username}, Email: ${email}, Password: ${password}`);

  if (!username) {
    html += "Username is required<br>";
  }
  if (!email) {
    html += "Email is required<br>";
  }
  if (!password) {
    html += "Password is required<br>";
  } else {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/signup");
      return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
      email: email,
      username: username,
      password: hashedPassword,
    });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  }

  if (!username || !email || !password) {
    html += `<a href="/signup">Try again</a>`;
  }

  html += `</p>`;

  res.send(html);
});

app.get("/login", (req, res) => {
  var html = `
     <form action="/loggingin" method="POST">
        <label for="email">Email:</label><br>
        <input type="email" id="email" name="email"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Submit">
    </form>
     `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // Joi schema to validate both fields (prevents NoSQL injection)
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });

  if (validationResult.error != null) {
    console.log("Invalid input: ", validationResult.error);
    return res.send(`
        <p>Invalid input. Please check your email and password format.</p>
        <a href="/login">Try again</a>
      `);
  }

  // Query user from MongoDB
  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, password: 1, username: 1 })
    .toArray();

  if (result.length !== 1) {
    console.log("User not found");
    return res.send(`
        <p>User not found.</p>
        <a href="/login">Try again</a>
      `);
  }

  // Compare passwords using bcrypt
  const passwordMatch = await bcrypt.compare(password, result[0].password);

  if (passwordMatch) {
    console.log("Login successful");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
  } else {
    console.log("Incorrect password");
    return res.send(`
        <p>Incorrect password.</p>
        <a href="/login">Try again</a>
      `);
  }
});

app.get("/members", (req, res) => {
  if (req.session.authenticated) {
    const images = ["isfahan.jpg", "mosque.jpg", "golestan.jpg"];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    var html = `
        <h1>Welcome to the members page!</h1>
        <p>Hello ${req.session.username}!</p>
        <img src="/${randomImage}" alt="Random Image" width="300"/><br><br>
        <button><a href="/logout">Logout</a></button>
        `;
    res.send(html);
  } else {
    res.redirect("/");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.get("/*dummy", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
