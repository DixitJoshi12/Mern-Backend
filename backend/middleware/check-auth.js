const HttpError = require('../models/http-error');
const jwt = require('jsonwebtoken');

module.exports = (req,res,next) => {
    // token will not come in body as get and delete requests doesn't required data 
    // a good way is to send the token in headers rather in query string
    if(req.method === 'OPTIONS'){
        return next();
    }
    try{
        const token = req.headers.authorization.split(' ')[1];
        if(!token){
            return next(new HttpError(`Authentication Failed no token`,403)); 
        }
        const decodedToken = jwt.verify(token,'supersecret_dont_share');
        // placing the the userId to the req
        req.userData = {userId : decodedToken.userId};
        next();
    }catch(err){
        return next(new HttpError(`Authentication Failed `,403)); 
    }
}