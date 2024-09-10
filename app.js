/////// app.js
const bcrypt = require('bcryptjs')
const { Pool } = require('pg')
const express = require('express')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
require('dotenv').config()

const pool = new Pool({
  host: process.env.DATABASE_HOST,
  user: process.env.USER,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
})

const app = express()
app.set('views', __dirname)
app.set('view engine', 'ejs')

app.use(session({ secret: 'cats', resave: false, saveUninitialized: false }))
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

app.use((req, res, next) => {
  res.locals.currentUser = req.user
  next()
})

app.get('/', (req, res) => {
  res.render('index', { user: req.user })
})
app.get('/sign-up', (req, res) => res.render('sign-up-form'))

app.post('/sign-up', async (req, res, next) => {
  try {
    // Hash the password before storing it
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return next(err) // If there's an error, handle it
      }

      // Store the hashed password in the database
      await pool.query(
        'INSERT INTO users (username, password) VALUES ($1, $2)',
        [
          req.body.username,
          hashedPassword, // Use the hashed password instead of the plain password
        ]
      )

      // Redirect or respond to the client
      res.redirect('/')
    })
  } catch (err) {
    return next(err) // Handle any database errors
  }
})

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      )
      const user = rows[0]

      if (!user) {
        return done(null, false, { message: 'Incorrect username' })
      }
      // if (user.password !== password) {
      //   return done(null, false, { message: 'Incorrect password' })
      // }
      const match = await bcrypt.compare(password, user.password)
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: 'Incorrect password' })
      }
      return done(null, user)
    } catch (err) {
      return done(err)
    }
  })
)

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id])
    const user = rows[0]

    done(null, user)
  } catch (err) {
    done(err)
  }
})

app.post(
  '/log-in',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  })
)

app.get('/log-out', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err)
    }
    res.redirect('/')
  })
})

app.listen(3000, () => console.log('app listening on port 3000!'))
