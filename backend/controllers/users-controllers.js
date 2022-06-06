const { validationResult } = require('express-validator');

const HttpError = require('../models/http-error');
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const getUsers = async (req, res, next) => {
  let users;
  try {
    users = await User.find({}, '-password');
  } catch (err) {
    const error = new HttpError(
      'Fetching users failed, please try again later.',
      500
    );
    return next(error);
  }
  res.json({ users: users.map(user => user.toObject({ getters: true })) });
};

const signup = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(
      new HttpError('Invalid inputs passed, please check your data.', 422)
    );
  }

  const { name, email, password } = req.body;

  let existingUser;
  try {
    existingUser = await User.findOne({ email: email });
  } catch (err) {
    const error = new HttpError(
      'Signing up failed, please try again later.',
      500
    );
    return next(error);
  }

  if (existingUser) {
    const error = new HttpError(
      'User exists already, please login instead.',
      422
    );
    return next(error);
  }

  let hashPassword;
  try{
    hashPassword = await bcrypt.hash(password,12);
  }catch(err){
    return next(new HttpError(`Couldn't create user, please try again`,500));
  }

  const createdUser = new User({
    name,
    email,
    image: req.file.path,
    password : hashPassword,
    places: [],
  });

  try {
    await createdUser.save();
  } catch (err) {
    const error = new HttpError(
      'Signing up failed, please try again later.',
      500
    );
    return next(error);
  }
  // once user is created we sent a twt token for authentication
  // json web token not return promise
  let token;
  try{
    token = jwt.sign({userId : createdUser.id , email : createdUser.email},'supersecret_dont_share',{expiresIn : '1h'});
  }catch(err){
    return next(new HttpError(`token creation failed`,500));
  }
  res.status(201).json({ userId : createdUser.id, email : createdUser.email, token : token });
};

const login = async (req, res, next) => {
  const { email, password } = req.body;

  let existingUser;

  try {
    existingUser = await User.findOne({ email: email });
  } catch (err) {
    const error = new HttpError(
      'Loggin in failed, please try again later.',
      500
    );
    return next(error);
  }

  if (!existingUser) {
    const error = new HttpError(
      'Invalid credentials, could not log you in.',
      403
    );
    return next(error);
  }
  let isValidPassword = false;
  try{
    isValidPassword = await bcrypt.compare(password,existingUser.password);
  }catch(err){
    return next(new HttpError("Couldn't logged in user, please check your credentials",500));
  }
  if(!isValidPassword){
    return next(new HttpError("Couldn't logged in user, please check your credentials",403));
  }

  // create jwt
  let token;
  try{
    token = jwt.sign({userId : existingUser.id , email : existingUser.email},'supersecret_dont_share',{expiresIn : '1h'});
  }catch(err){
    return next(new HttpError(`Couldn't create user in login, please try again`,500));
  }

  res.json({
    userId : existingUser.id,
    email : existingUser.email,
    token : token
  });
};

exports.getUsers = getUsers;
exports.signup = signup;
exports.login = login;
