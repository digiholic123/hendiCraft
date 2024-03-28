const { ObjectId } = require('mongodb');
const mongoose = require('mongoose');
const { Schema } = mongoose;

const adminSchema = new Schema({
  email: { type: String },
  password: { type: String },
  address: { type: String },
  isDeleted: { type: Boolean, default: 0 },
  code: { type: Number },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model('admin', adminSchema)