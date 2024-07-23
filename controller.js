// const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const path = require('path');
const { User, OTP  } = require('./model');
const { sendGmail } = require('./mailer');
const { signupSchema, verifySignupOTPSchema , loginSchema, resetPasswordSchema, forgotPasswordSchema , updateProfileSchema, resendOTPSchema  } = require('./validation');

// Add your secret key for JWT
const JWT_SECRET = '7988';


// Signup Controller
exports.signup = async (req, res) => {
  const { error } = signupSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email, phone, countryCode, password } = req.body;

  try {
    let user = null;

    // Check if email already exists in User
    if (email) {
      user = await User.findOne({ email });
      if (user && user.verified) {
        return res.status(400).json({ message: 'Email already in use.' });
      }
    }

    // Check if phone already exists in User
    if (phone) {
      user = await User.findOne({ phone });
      if (user && user.verified) {
        return res.status(400).json({ message: 'Phone already in use.' });
      }
    }

    // Determine if user exists and hash password if necessary
    const hashedPassword = user ? user.password : await bcrypt.hash(password, 10);

    // Prepare update object based on provided data
    const update = {
      password: hashedPassword,
      verified: false,
      countryCode,
      ...(email && { email }), // Only add email if it's provided
      ...(phone && { phone })    // Only add phone if it's provided
    };

    // Create or update user with provided data
    user = await User.findOneAndUpdate(
      { $or: [{ email }, { phone }] },
      update,
      { upsert: true, new: true, strict: false }
    );

    // Determine which OTP to generate
    const otp = '123456'; // Use a static OTP for verification
    const otpExpires = Date.now() + 300000; // 5 minutes from now

    // Upsert OTP based on whether email or phone is provided
    if (email) {
      await OTP.findOneAndUpdate(
        { email },
        { email, otp, otpExpires },
        { upsert: true, new: true }
      );

      // Send OTP to user's email
      sendGmail(email, 'Signup OTP', `Your OTP is ${otp}`);
      return res.status(200).json({ message: 'OTP sent to email.' });
    }

    if (phone) {
      await OTP.findOneAndUpdate(
        { phone },
        { phone, otp, otpExpires },
        { upsert: true, new: true }
      );

      return res.status(200).json({ message: 'OTP sent to phone.' });
    }

    return res.status(400).json({ message: 'Email or phone is required.' });
  } catch (error) {
    console.error('Error in signup:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};



exports.verifySignupOTP =async (req, res) => {
  const { error } = verifySignupOTPSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email, phone, otp } = req.body;

  try {
    let otpEntry;
    if (phone) {
      otpEntry = await OTP.findOne({ phone, otp });
    } else if (email) {
      otpEntry = await OTP.findOne({ email, otp });
    } else {
      return res.status(400).json({ message: 'Email or phone is required.' });
    }

    if (!otpEntry || otpEntry.otpExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }

    // Delete OTP entry and update user verification status
    if (phone) {
      await OTP.deleteOne({ phone, otp });
      await User.updateOne({ phone }, { verified: true });
    } else if (email) {
      await OTP.deleteOne({ email, otp });
      await User.updateOne({ email }, { verified: true });
    }

    return res.status(200).json({ message: 'Verified User Created successfully.' });
  } catch (error) {
    console.error('Error in verifySignupOTP:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// Login Controller
exports.login = async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email, phone, password } = req.body;
  try {
    let user;
    if (email) {
      user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: 'User with this email does not exist' });
      }
    } else if (phone) {
      user = await User.findOne({ phone });
      if (!user) {
        return res.status(400).json({ message: 'User with this phone does not exist' });
      }
    } else {
      return res.status(400).json({ message: 'Email or phone is required' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    return res.status(200).json({
      token,
      message: 'User logged in successfully',
      user: {
        id: user._id,
        email: user.email,
        phone: user.phone,
        
      },
    });
  } catch (error) {
    console.error('Error in login:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// Get Profile Controller
exports.getProfile = async (req, res) => {
  return res.status(200).json({ Userdata : req.user });
};

// Update Profile Controller 
exports.updateProfile = async (req, res) => {
  try {
    const { error } = updateProfileSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const user = req.user; // Assuming req.user contains the authenticated user's data
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const updatedFields = req.body;

    // Update user profile fields
    Object.assign(user, updatedFields);

    // Save updated user profile in the database
    await user.save();

    // Respond with updated user details
    res.json({
      message: 'Profile updated successfully',
      userData: user
    });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
};


exports.resendOTP = async (req, res) => {
  const { error } = resendOTPSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email } = req.body;
  try {

    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.verified) {
      return res.status(400).json({ message: 'Email is already verified.' });
    }
    
    // Generate OTP
    // const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otp = 123456;
    const otpExpires = Date.now() + 300000; // 5 minutes from now

    // Update or insert OTP
    await OTP.findOneAndUpdate(
      { email },
      { email, otp, otpExpires },
      { upsert: true, new: true }
    );

    // Send OTP email
    await sendGmail(email, 'Signup OTP', `Your OTP is ${otp}`);
    return res.status(200).json({ message: 'OTP resent to email.' });
  } catch (error) { 
    // console.error('Error in resendOTP:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// Change Password Controller
exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // Validate old and new passwords
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ message: 'Old password and new password are required.' });
    }

    const user = req.user; // Assuming req.user contains the authenticated user's data
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if oldPassword matches user's current password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Old password is incorrect.' });
    }

    // Hash the new password and update user's password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Save updated user profile in the database
    await user.save();

    // Respond with success message
    res.json({ message: 'Password changed successfully.' });
  } catch (error) {
    console.error('Error in changing password:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


exports.forgotPassword = async (req, res) => {
  const { error } = forgotPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Save reset token and expiration to the database
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send reset password link to user's email
    const resetLink = `http://localhost:${process.env.PORT}/api/resetPassword?token=${resetToken}&email=${email}`;
  const subject = 'Password Reset Request';
  const text = `Click the link to reset your password: ${resetLink}`;
  const html = `<p>Click the link to reset your password: <a href="${resetLink}">${resetLink}</a></p>`;

  await sendGmail(email, subject, text, html);


  res.status(200).json({ message: 'Password reset link sent successfully' });
  } catch (error) {
    console.error('Error in forgotPassword:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};



exports.resetPassword = async (req, res) => {
  const { error } = resetPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { newPassword } = req.body;
  const { token , email} = req.query;

  try {
    // Find user with the reset token and ensure it hasn't expired
    const user = await User.findOne({
      email,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });
     
    if (!user) { 
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Update user password and clear reset token and expiration
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error in resetPassword:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.deleteAccount = async (req, res) => {
  const { email } = req.body;

  // Delete user account
  await User.deleteOne({ email });

  res.status(200).json({ message: 'User account deleted successfully' });
};


// Upload Profile Image Controller
exports.uploadProfileImage = async (req, res) => {
  // console.log('req: ', req);
  try {
    const userId = req.user._id;
    const imagePath = path.join('uploads', req.file.filename);
    // console.log('imagePath: ', imagePath);  
    // console.log('req.file.filename: ', req.file);

    // Update the user's profile with the image path
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.profileImage = imagePath;
    await user.save();

    const baseURL = process.env.BASE_URL || `http://localhost:${port}`;
    const fullImageURL = `${baseURL}/uploads/${req.file.filename}`;

    res.json({
      message: 'Profile image uploaded successfully.',
      user: {
        userId: user._id,
        image: fullImageURL,
      }
    });
  } catch (error) {
    console.error('Error in uploading profile image:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
}; 



