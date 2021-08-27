require('dotenv').config();
const jwt = require('jsonwebtoken');
const { userAuthError, endpointAuthError } = require('../utils/errors');
const UnauthorizedError = require('../errors/unauthorized');
const ForbiddenError = require('../errors/forbidden');

module.exports = (req, res, next) => {
  const { token } = req.cookies;
  const { NODE_ENV, JWT_SECRET } = process.env;

  if (!token) {
    throw new UnauthorizedError(userAuthError);
  }

  let payload;

  try {
    payload = jwt.verify(token, NODE_ENV === 'production' ? JWT_SECRET : 'dev-secret');
  } catch (err) {
    throw new ForbiddenError(endpointAuthError);
  }

  req.user = payload;

  next();
};
