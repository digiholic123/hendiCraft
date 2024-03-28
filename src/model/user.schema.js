const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String },
  phone: { type: Number },
  email: { type: String },
  password: { type: String },
  address: { type: String },
  isDeleted: { type: Boolean, default: 0 },
  isVerified: { type: Boolean, default: 0 },
  code: { type: Number },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model('users', userSchema);
