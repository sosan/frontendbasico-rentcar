const express = require('express');
const router = express.Router();
const path = require("path");

// controladores
const home = require("../controllers/inicio");



// rutas
router.get("/", async (req, res) => await home.getHome(req, res));
router.get("/.well-known/acme-challenge/*", async (req, res) =>
{
    res.sendFile(path.join(__dirname, "../../public/.well-known/acme-challenge/texto"));

});



module.exports = router;