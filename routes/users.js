const express = require('express');
const router = express.Router();

//login Page
router.get('/login', (req, res) => {
  res.render('Login');
});

//Register Page
router.get('/register', (req, res) => {
    res.render('Register');
  });
module.exports = router;