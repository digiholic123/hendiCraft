// Import required modules
const db = require('../config/db'); // Import database configuration
const Admin = db.Admin; // Import the Admin model from the database
const { hashPassword, comparePassword, generateRandomNumber } = require('../helper/middleware'); // Import middleware functions for password hashing, comparison, and random number generation
const jwt = require('jsonwebtoken'); // Import JSON Web Token module for authentication
const secretKey = process.env.JWT_SECRET_KEY; // Get secret key from environment variables for JWT signing
const CryptoJS = require('crypto-js'); // Import CryptoJS module for cryptographic functions
const sendMail = require('../helper/email'); // Import function for sending emails
const bcrypt = require('bcryptjs'); // Import bcryptjs module for password hashing and comparison

// Function to handle admin login
exports.adminLogin = async (req, res) => {
    try {
        let { email, password } = req.body; // Destructure email and password from request body
        let isAdminExists = await Admin.findOne({ email: email }); // Check if admin exists with the provided email
        if (isAdminExists && isAdminExists !== null) { // If admin exists
            let pass = isAdminExists.password; // Get hashed password from database
            let checkPassword = await bcrypt.compare(password, pass); // Compare provided password with hashed password
            if (checkPassword) { // If passwords match
                const payload = { adminId: isAdminExists._id }; // Create payload for JWT token
                const token = jwt.sign(payload, secretKey, { expiresIn: '1h' }); // Generate JWT token with expiration time of 1 hour
                return res.status(200).send({ // Send success response with token
                    status: true,
                    msg: "admin login succesfully",
                    token: token
                });
            } else { // If passwords don't match
                return res.status(200).send({ // Send failure response for invalid password
                    status: false,
                    msg: "Invalid password",
                });
            }
        } else { // If admin doesn't exist with provided email
            return res.status(200).send({ // Send failure response for invalid email
                status: false,
                msg: "Invalid email",
            });
        }
    } catch (error) { // Catch any errors that occur during execution
        return res.status(500).send({ // Send error response for internal server error
            status: false,
            msg: "Something went wrong"
        });
    }
};

// Function to handle admin change password
exports.adminChangePassword = async (req, res) => {
    try {
        let id = req.decoded.adminId; // Get admin ID from JWT token
        let { old_password, new_password } = req.body; // Destructure old_password and new_password from request body
        let isAdminExists = await Admin.findOne({ _id: id }); // Check if admin exists with the provided ID
        if (isAdminExists && isAdminExists !== null) { // If admin exists
            let getOldPassword = isAdminExists.password; // Get hashed password from database
            let checkPassword = await bcrypt.compare(old_password, getOldPassword); // Compare provided old password with hashed password
            if (checkPassword) { // If old passwords match
                let newPassword = await hashPassword(new_password); // Hash the new password
                const filter = { _id: id }; // Define filter for update operation
                const update = { // Define update operation to set new password
                    $set: {
                        password: newPassword
                    },
                };
                const check = await Admin.updateOne(filter, update); // Update admin password
                if (check) { // If password update is successful
                    return res.status(200).send({ // Send success response
                        status: true,
                        msg: "Password Change Sucessfully",
                    });
                } else { // If password update fails
                    return res.status(200).send({ // Send failure response
                        status: true,
                        msg: "Password not Change",
                    });
                }
            } else { // If old passwords don't match
                return res.status(200).send({ // Send failure response for invalid password
                    status: false,
                    msg: "Invalid password",
                });
            }
        } else { // If admin doesn't exist with provided ID
            return res.status(200).send({ // Send failure response for invalid admin
                status: false,
                msg: "Admin Not Exists",
            });
        }
    } catch (error) { // Catch any errors that occur during execution
        return res.status(500).send({ // Send error response for internal server error
            status: false,
            msg: "Something went wrong"
        });
    }
};


// Function to handle sending OTP for admin password reset
exports.adminForgetPasswordSendOtpFn = async (req, res) => {
    try {
        let { email } = req.body; // Extract email from request body
        let isAdminExists = await Admin.findOne({ email: email }); // Check if admin exists with provided email
        if (isAdminExists) { // If admin exists
            const randomNumber = await generateRandomNumber(10000, 20000); // Generate a random number as OTP
            const filter = { email: email }; // Define filter for admin
            const update = { // Define update operation to set OTP code
                $set: {
                    code: randomNumber
                },
            };
            const check = await Admin.updateOne(filter, update); // Update admin with new OTP code
            if (check) { // If update is successful
                let emailSendFunction = await sendMail.mail(email, randomNumber); // Send email with OTP
                return res.status(200).send({ // Send success response
                    status: true,
                    msg: "otp send succesfully",
                });
            }
        } else { // If admin doesn't exist with provided email
            return res.status(200).send({ // Send failure response
                status: true,
                msg: "Admin not found"
            });
        }
    } catch (error) { // Catch any errors that occur during execution
        return res.status(500).send({ // Send error response for internal server error
            status: false,
            msg: "Something went wrong"
        });
    }
};

// Function to handle admin password reset
exports.adminForgetPasswordFn = async (req, res) => {
    try {
        let { email, otp, password } = req.body; // Extract email, OTP, and new password from request body
        let isAdminExists = await Admin.findOne({ email: email }); // Check if admin exists with provided email
        if (isAdminExists) { // If admin exists
            let code = isAdminExists.code; // Get OTP code from admin record
            if (code == otp) { // If provided OTP matches the stored OTP
                let newPassword = await hashPassword(password); // Hash the new password
                const filter = { email: email }; // Define filter for admin
                const update = { // Define update operation to set new password
                    $set: {
                        password: newPassword
                    },
                };
                const check = await Admin.updateOne(filter, update); // Update admin with new password
                if (check) { // If update is successful
                    return res.status(200).send({ // Send success response
                        status: true,
                        msg: "Your Password Has Been Reset Succesfully",
                    });
                } else { // If update fails
                    return res.status(200).send({ // Send failure response
                        status: true,
                        msg: "Your Password Not Be Reset",
                    });
                }
            } else { // If provided OTP does not match the stored OTP
                return res.status(200).send({ // Send failure response
                    status: true,
                    msg: "Invalid otp",
                });
            }
        } else { // If admin doesn't exist with provided email
            return res.status(200).send({ // Send failure response
                status: true,
                msg: "Admin not found"
            });
        }
    } catch (error) { // Catch any errors that occur during execution
        return res.status(500).send({ // Send error response for internal server error
            status: false,
            msg: "Something went wrong"
        });
    }
};

