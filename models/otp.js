import mongoose from 'mongoose';

const OTPSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: '10m' } // OTP expires in 10 minutes
});

// Index for faster email lookups
OTPSchema.index({ email: 1 });

const OTP = mongoose.model('OTP', OTPSchema);

export default OTP;