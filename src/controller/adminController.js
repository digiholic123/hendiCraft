// Import required modules
const db = require('../config/db');
const Admin = db.Admin; 
const { hashPassword, comparePassword, generateRandomNumber } = require('../helper/middleware'); 
const jwt = require('jsonwebtoken'); 
const secretKey = process.env.JWT_SECRET_KEY; 
const CryptoJS = require('crypto-js'); 
const sendMail = require('../helper/email'); 
const bcrypt = require('bcryptjs'); 

// Function to handle admin login
exports.adminLogin = async (req, res) => {
    try {
        let { email, password } = req.body;
        let isAdminExists = await Admin.findOne({ email: email });
        if (isAdminExists && isAdminExists !== null) {
            let pass = isAdminExists.password;
            let checkPassword = await bcrypt.compare(password, pass);
            if (checkPassword) {
                const payload = { adminId: isAdminExists._id };
                const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });
                return res.status(200).send({
                    status: true,
                    msg: "admin login succesfully",
                    token: token
                });
            } else {
                return res.status(200).send({
                    status: false,
                    msg: "Invalid password",
                });
            }
        } else {
            return res.status(200).send({
                status: false,
                msg: "Invalid email",
            });
        }
    } catch (error) {
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
};

// Function to handle admin change password
exports.adminChangePassword = async (req, res) => {
    try {
        let id = req.decoded.adminId;
        let { old_password, new_password } = req.body;
        let isAdminExists = await Admin.findOne({ _id: id });
        if (isAdminExists && isAdminExists !== null) {
            let getOldPassword = isAdminExists.password;
            let checkPassword = await bcrypt.compare(old_password, getOldPassword);
            if (checkPassword) {
                let newPassword = await hashPassword(new_password);
                const filter = { _id: id };
                const update = {
                    $set: {
                        password: newPassword
                    },
                };
                const check = await Admin.updateOne(filter, update);
                if (check) {
                    return res.status(200).send({
                        status: true,
                        msg: "Password Change Sucessfully",
                    });
                } else {
                    return res.status(200).send({
                        status: true,
                        msg: "Password not Change",
                    });
                }
            } else {
                return res.status(200).send({
                    status: false,
                    msg: "Invalid password",
                });
            }
        } else {
            return res.status(200).send({
                status: false,
                msg: "Admin Not Exists",
            });
        }
    } catch (error) {
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
};

// Function to handle sending OTP for admin password reset
exports.adminForgetPasswordSendOtpFn = async (req, res) => {
    try {
        let { email } = req.body;
        let isAdminExists = await Admin.findOne({ email: email });
        if (isAdminExists) {
            const randomNumber = await generateRandomNumber(10000, 20000);
            const filter = { email: email };
            const update = {
                $set: {
                    code: randomNumber
                },
            };
            const check = await Admin.updateOne(filter, update);
            if (check) {
                let emailSendFunction = await sendMail.mail(email, randomNumber);
                return res.status(200).send({
                    status: true,
                    msg: "otp send succesfully",
                });
            }
        } else {
            return res.status(200).send({
                status: true,
                msg: "Admin not found"
            });
        }
    } catch (error) {
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
};

// Function to handle admin password reset
exports.adminForgetPasswordFn = async (req, res) => {
    try {
        let { email, otp, password } = req.body;
        let isAdminExists = await Admin.findOne({ email: email });
        if (isAdminExists) {
            let code = isAdminExists.code;
            if (code == otp) {
                let newPassword = await hashPassword(password);
                const filter = { email: email };
                const update = {
                    $set: {
                        password: newPassword
                    },
                };
                const check = await Admin.updateOne(filter, update);
                if (check) {
                    return res.status(200).send({
                        status: true,
                        msg: "Your Password Has Been Reset Succesfully",
                    });
                } else {
                    return res.status(200).send({
                        status: true,
                        msg: "Your Password Not Be Reset",
                    });
                }
            } else {
                return res.status(200).send({
                    status: true,
                    msg: "Invalid otp",
                });
            }
        } else {
            return res.status(200).send({
                status: true,
                msg: "Admin not found"
            });
        }
    } catch (error) {
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
};