const jwt = require('jsonwebtoken');

function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];  // Format of header is 'Bearer TOKEN'

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403); // Forbidden
            }

            req.userId = user.id;
            next();
        });
    } else {
        res.sendStatus(401);  // Unauthorized
    }
}

module.exports = authenticateJWT;