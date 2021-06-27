const express = require('express');
const router = express.Router();

// controladores
const home = require("../controllers/inicio");



// rutas
router.get("/", async (req, res) => await home.getHome(req, res));




module.exports = router;