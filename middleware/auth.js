const jwt = require('jsonwebtoken');

module.exports = function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) {
    return res.redirect('/login');
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret_change_me');
    req.user = { id: payload.sub, name: payload.name, email: payload.email };
    res.locals.user = req.user;
    return next();
  } catch (err) {
    res.clearCookie('token', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
    return res.redirect('/login');
  }
};
