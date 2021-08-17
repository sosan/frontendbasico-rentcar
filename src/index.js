
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const express = require('express');
const eta = require("eta");
const compression = require('compression');
const userAgent = require('express-useragent')
const rateLimit = require('express-rate-limit');
// const session = require('express-session');
const router = require('./routes/route');
const path = require("path");


const app = express();

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, //1min
    max: 20
});


// politicas de seguridad
app.use(
    helmet.contentSecurityPolicy(
        {
            useDefaults: false,
            directives: {
                reportUri: ["https://gate.rapidsec.net/g/r/csp/616afffa-f826-4461-85c3-941ee6973aff/0/0/3?sct=30c0d50e-2191-4857-9e5d-aed703100472&dpos=report"],
                baseUri: ["'self'"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                manifestSrc: ["'self'"],
                mediaSrc: ["'self'"],
                defaultSrc: ["'none'"],
                imgSrc: ["'self'"],
                objectSrc: ["'none'"],
                styleSrc: [
                    "'self'",
                    "'unsafe-hashes'",
                    "https://sis-t.redsys.es:25443/sis/NC/sandbox/redsysV2.js",
                    "https://sis.redsys.es/sis/NC/redsysV2.js",
                    "'sha256-QhTxUtlV491XQZHnTX/iZgDCdfTbN1vAILK4yt3jgYI='",
                    "'sha256-7QjiizGaIV/0HdTo3IYJW3cdwZC5lF69KZWWFmTz8Gw='",
                    "'unsafe-inline'"

                ],
                styleSrcAttr: [
                    "'self'",
                    "'unsafe-hashes'",
                    "https://sis-t.redsys.es:25443/sis/NC/sandbox/redsysV2.js",
                    "https://sis.redsys.es/sis/NC/redsysV2.js",
                    "'sha256-QhTxUtlV491XQZHnTX/iZgDCdfTbN1vAILK4yt3jgYI='",
                    "'sha256-7QjiizGaIV/0HdTo3IYJW3cdwZC5lF69KZWWFmTz8Gw='",
                    "https://sis-t.redsys.es:25443/",
                    "https://sis.redsys.es",
                    "'unsafe-inline'"

                ],
                formAction: ["'self'"],
                workerSrc: ["'self'"],
                scriptSrc: [
                    "'self'",
                    "https://www.google.com/maps/embed",
                    "https://maps.googleapis.com/maps/api/js/QuotaService.RecordEvent",
                    "https://sis-t.redsys.es:25443/sis/NC/sandbox/redsysV2.js",
                    "https://sis.redsys.es/sis/NC/redsysV2.js",
                    "'sha256-S+X8s301GQoAcOI+8hj231fxePS+QG94YC0px7AraoQ='",
                    "'sha256-Z6AFHJcDDPHLaWVdLcifmBDDzjDMApb7nM2qbkPTJeo='",
                    "'sha256-YVCjXA9IbEbK3w4jDiqhWcfCPs+7VhG2TuPyX8v/NB8='",
                    "'sha256-V7W7QXt7q8HLNfscNP1nsRRepxg+sOz7CfsY1z6EzfY='",
                    "'sha256-iGoNEAX01mPhFHPIHqILK51hg3IxPfVSI9LFcd/8Vpg='",
                    "'sha256-PZEg+mIdptYTwWmLcBTsa99GIDZujyt7VHBZ9Lb2Jys='",
                    "'sha256-c7UrMTK2hnfEDAZh1ENjqCJcH/9cqaKMEMPjIE9RUFM='",
                    "'sha256-5YNcDGqyZeDxGr9YmU6qLTlPX3Cgq14oFpH7CX5CXgM='",
                    "'sha256-tSulbyIC9pCfjTMSJ+oGN0txgCAxkNMdf3mNyhvqLd8='",

                    "'unsafe-inline'",
                ],
                scriptSrcElem: [
                    "'self'",
                    "https://www.google.com/maps/embed",
                    "https://maps.googleapis.com/maps/api/js/QuotaService.RecordEvent",
                    "https://sis-t.redsys.es:25443/sis/NC/sandbox/redsysV2.js",
                    "https://sis.redsys.es/sis/NC/redsysV2.js",
                    "'sha256-S+X8s301GQoAcOI+8hj231fxePS+QG94YC0px7AraoQ='",
                    "'sha256-Z6AFHJcDDPHLaWVdLcifmBDDzjDMApb7nM2qbkPTJeo='",
                    "'sha256-YVCjXA9IbEbK3w4jDiqhWcfCPs+7VhG2TuPyX8v/NB8='",
                    "'sha256-V7W7QXt7q8HLNfscNP1nsRRepxg+sOz7CfsY1z6EzfY='",
                    "'sha256-iGoNEAX01mPhFHPIHqILK51hg3IxPfVSI9LFcd/8Vpg='",
                    "'sha256-PZEg+mIdptYTwWmLcBTsa99GIDZujyt7VHBZ9Lb2Jys='",
                    "'sha256-c7UrMTK2hnfEDAZh1ENjqCJcH/9cqaKMEMPjIE9RUFM='",
                    "'sha256-5YNcDGqyZeDxGr9YmU6qLTlPX3Cgq14oFpH7CX5CXgM='",
                    "'sha256-tSulbyIC9pCfjTMSJ+oGN0txgCAxkNMdf3mNyhvqLd8='"

                ],
                childSrc: ["'self'", "https://apis.google.com", "https://maps.googleapis.com", "https://www.google.com", "https://sis-t.redsys.es:25443/"],
                frameSrc: [
                    "'self'",
                    "https://apis.google.com",
                    "https://maps.googleapis.com",
                    "https://www.google.com",
                    "https://sis-t.redsys.es:25443/",
                    "https://sis.redsys.es/",
                ],

                frameAncestors: ["'none'"],
                upgradeInsecureRequests: [],
                blockAllMixedContent: [],
            },
        })
);

app.use(helmet.dnsPrefetchControl());
app.use(helmet.expectCt());

// // X-Frame-Options
// app.use(helmet.frameguard({
//     action: "deny",
// }));

app.use(helmet.hidePoweredBy());
app.use(helmet.hsts());
app.use(helmet.ieNoOpen());

// // X-Content-Type-Options: nosniff
app.use(helmet.noSniff());

// // X-Permitted-Cross-Domain-Policies: none
// app.use(
//     helmet.permittedCrossDomainPolicies({
//         permittedPolicies: "by-content-type",
//     })
// );


// Cross-Origin-Embedder-Policy: require-corp
// app.use(helmet.crossOriginEmbedderPolicy({ policy: "require-corp" }));

// Cross-Origin-Opener-Policy: same-origin
app.use(helmet.crossOriginOpenerPolicy({ policy: "same-origin-allow-popups" }));

// Cross-Origin-Resource-Policy: same-origin
// app.use(helmet.crossOriginResourcePolicy(
//         { policy: "cross-origin" }
// ));

// Referrer-Policy
app.use(helmet.referrerPolicy({
    policy: "no-referrer",
}));
app.use(helmet.xssFilter());


// configuracion

app.use(compression());
app.use(userAgent.express());

app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json({ limit: '2mb' }));



app.use(morgan('combined'));

//registro de html como eta
app.engine(".html", eta.renderFile);
app.set("views", path.join(__dirname, "../public"));
app.set("view engine", "html");

app.use("/", express.static('public'));

// rutas
app.use("/", apiLimiter);
app.use("/", router);

const portStatic = 8085;
// escucha puerto servidor
app.listen(portStatic, (error) => {
    if (error) {
        console.error(`[process ${process.pid}] Error ${error} ${portStatic}`);
    }
    console.info(`[process ${process.pid}] Listening at port ${portStatic}`);
}
);

exports.app = app;

