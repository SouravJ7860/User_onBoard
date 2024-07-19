const express = require('express');
const router = express.Router();
const upload = require('./config/multerConfig');
const {
  signup,
  verifySignupOTP,
  login,
  getProfile,
  updateProfile,
  resendOTP,
  changePassword,
  forgotPassword,
  resetPassword,
  deleteAccount,
  uploadProfileImage
 
} = require('./controller');


const checkUserExists  = require('./userMiddleware').checkUserExists
const authToken  =  require('./authmiddleware') ;

// Signup Routes
router.post('/signup', checkUserExists, signup);
router.post('/verify-signup-otp', verifySignupOTP);
router.post('/resend-signup-otp' , resendOTP);

// Login Route
router.post('/login', login);

// Profile Routes
router.get('/profile',authToken, getProfile);
router.patch('/profile',authToken, updateProfile);

// Other Routes (e.g., forgot password)
router.post('/change-password', authToken, changePassword);
router.post('/forgot-password',authToken, forgotPassword);
router.post('/resetPassword', resetPassword);
router.post('/delete-account',deleteAccount);

// POST route for uploading profile image
router.post('/upload-profile-image',authToken,  upload.single('image'), uploadProfileImage);

module.exports = router;
