import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

// Initialize Express app
const app = express();
const port = 3000;
const saltRounds = 10;
env.config(); // Load environment variables from .env file

// Middleware setup
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Session secret key
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.static("public")); // Serve static files from the 'public' directory

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Initialize PostgreSQL client
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect(); // Connect to PostgreSQL database

// Routes

// Home page route
app.get("/", (req, res) => {
  res.render("home.ejs"); // Render home page template
});

// Login page route
app.get("/login", (req, res) => {
  res.render("login.ejs"); // Render login page template
});

// Registration page route
app.get("/register", (req, res) => {
  res.render("register.ejs"); // Render registration page template
});

// Logout route
app.get("/logout", (req, res) => {
  req.logout(function (err) { // Logout user
    if (err) {
      return next(err);
    }
    res.redirect("/"); // Redirect to home page after logout
  });
});

// Secrets page route
app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) { // Check if user is authenticated
    try {
      // Query database for user's secret
      const result = await db.query(
        `SELECT secret FROM users WHERE email = $1`,
        [req.user.email]
      );
      const secret = result.rows[0].secret; // Retrieve user's secret
      if (secret) {
        res.render("secrets.ejs", { secret: secret }); // Render secrets page with user's secret
      } else {
        res.render("secrets.ejs", { secret: "Jack Bauer is my hero." }); // Default secret if user has none
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login"); // Redirect to login page if user is not authenticated
  }
});

// Submit page route
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs"); // Render submit page if user is authenticated
  } else {
    res.redirect("/login"); // Redirect to login page if user is not authenticated
  }
});

// Google authentication route
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

// Google authentication callback route
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Login post route
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Registration post route
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          // Insert new user into database
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// Submit post route
app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;
  try {
    // Update user's secret in the database
    await db.query(`UPDATE users SET secret = $1 WHERE email = $2`, [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

// Passport local strategy configuration
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      // Query database for user with given email
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user); // User authenticated
            } else {
              return cb(null, false); // Invalid password
            }
          }
        });
      } else {
        return cb("User not found"); // User not found
      }
    } catch (err) {
      console.log(err);
    }
  })
);

// Passport Google strategy configuration
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // Check if user exists in the database
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          // If user does not exist, insert into database
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]); // Return user if exists
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
