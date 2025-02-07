const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

const app = express();
const port = process.env.PORT || 3000;
// for parsing application/json
app.use(express.json()); 
//  Array to store users temporarily. In a real application, we would use a database.
const users = [];

// Another array to store high scores. In a real application, we will replace with database
const highScores = [];

// Secret key used for signing JSON Web Tokens (JWT). In a real application, we will make sure to use a strong, secure key and  will keep it secret.
const secretKey = "your_secret_key"; 


function createToken(payload) {
  return jwt.sign(payload, secretKey, { expiresIn: "1h" });
}

function validateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1]; 
  if (!token) return res.status(401).send("Token is required.");

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(401).send("Invalid token.");
    req.user = decoded;
    next();
  });
}

// Middleware to validate request
function validateRequest(rules) {
  return [
    ...rules,
    (req, res, next) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const allowedFields = rules.map(rule => rule.builder.fields[0]);
      const receivedFields = Object.keys(req.body);
      const extraFields = receivedFields.filter(field => !allowedFields.includes(field));

      if (extraFields.length > 0) {
        return res.status(400).json({ errors: [{ msg: `Invalid fields: ${extraFields.join(", ")}` }] });
      }
      next();
    }
  ];
}

// Register a new user
app.post('/signup', validateRequest([
  body('userHandle').isString().isLength({ min: 6 }).notEmpty(),
  body('password').isString().isLength({ min: 6 }).notEmpty()
]), async (req, res) => {
  const { userHandle, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ userHandle, password: hashedPassword });
  res.status(201).send('User registered successfully.');
});

// Login and receive JWT token
app.post('/login', validateRequest([
  body('userHandle').isString().notEmpty(),
  body('password').isString().notEmpty()
]), async (req, res) => {
  const { userHandle, password } = req.body;
  const user = users.find(user => user.userHandle === userHandle);
  if (!user) return res.status(401).send('Invalid credentials.');

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(401).send('Invalid credentials.');

  const token = createToken({ userHandle });
  res.json({ jsonWebToken: token });
});

// Post high score (Protected with JWT)
app.post('/high-scores', validateToken, validateRequest([
  body('level').isString().notEmpty(),
  body('score').isInt({ min: 0 }),
  body('timestamp').isISO8601(),
  body('userHandle').isString().notEmpty()
]), (req, res) => {
  const { level, score, timestamp, userHandle } = req.body;
  highScores.push({ userHandle, level, score, timestamp });
  res.status(201).send('High score posted successfully.');
});

// Get high scores with pagination
app.get('/high-scores', (req, res) => {
  const { level, page = 1 } = req.query;
  const limit = 20;
  const skip = (page - 1) * limit;
  const filteredScores = highScores.filter(score => score.level === level);
  const sortedScores = filteredScores.sort((a, b) => b.score - a.score);
  const paginatedScores = sortedScores.slice(skip, skip + limit);
  res.json(paginatedScores);
});


let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};
