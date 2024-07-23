const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: false },
  email: { type: String, required: function() { return !this.phone; }, unique: true , sparse: true },
  phone: { type: String, required: function() { return !this.email; }, unique: true ,  sparse: true },
  countryCode: { type: String , required: false },
  address: { type: String, required: false },
  password: { type: String, required: true },
  profileImage: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  verified: {type: Boolean, default: false},
  
}, { timestamps: true });

const otpSchema = new mongoose.Schema({
  email: {type: String,required: true},
  phone: {type: String, sparse: true },
  otp: {type: String,required: true},
  otpExpires: {type : Date, required: true},
});

module.exports = {
  User: mongoose.model('User', userSchema),
  OTP: mongoose.model('OTP', otpSchema),
};
