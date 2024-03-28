// Import necessary modules and dependencies
const db = require('../config/db'); // Import the database connection module (update the path accordingly)
const User = db.User; // Reference to the User model from the database
const { hashPassword, comparePassword, generateRandomNumber } = require('../helper/middleware'); // Import middleware functions for password hashing, comparison, and random number generation
const jwt = require('jsonwebtoken'); // Import JSON Web Token module for token generation
const secretKey = process.env.JWT_SECRET_KEY; // Secret key for JWT token signing
const CryptoJS = require('crypto-js'); // Import CryptoJS for encryption and decryption (not used in provided code)
const UserSchema = db.User; // Reference to the User schema from the database (duplicate reference, not used in provided code)
const sendMail = require('../helper/email'); // Import module for sending emails
const Msg = require('../helper/messages'); // Import module for storing messages/constants

const bcrypt = require('bcryptjs'); // Import bcrypt for password hashing and comparison

// Function to register a new user
exports.userRegister = async (req, res) => {
    try {
        // Extract user details from request body
        let { name, number, email, password, address } = req.body;

        // Check if the user already exists in the database
        let isUserExists = await User.findOne({ email: email });
        if (isUserExists) {
            // If user exists, return an error response
            return res.status(200).send({
                status: false,
                msg: Msg.emailExists,
            });
        } else {
            // Hash the password using bcrypt
            let newPassword = await hashPassword(password);

            // Generate a random number for verification code
            const randomNumber = await generateRandomNumber(10000, 20000);

            // Create an object to store user data
            let obj = {
                name: name,
                phone: number,
                email: email,
                password: newPassword,
                address: address,
                code: randomNumber
            };

            // Insert the user data into the database
            let data = UserSchema.insertMany(obj);

            // If data insertion is successful, send a verification email
            if (data) {
                let emailSendFunction = await sendMail.mail(email, randomNumber);
                return res.status(200).send({
                    status: true,
                    msg: Msg.registerSuccess,
                    data: data[0]
                });
            } else {
                // If data insertion fails, return an error response
                return res.status(200).send({
                    status: false,
                    msg: Msg.registerError
                });
            }
        }
    } catch (error) {
        // If an error occurs during registration process, return a server error response
        return res.status(500).send({
            status: false,
            msg: Msg.err
        });
    }
}

// Function to verify OTP
exports.otpVerifyfn = async (req, res) => {
    try {
        // Extract email and OTP from request body
        let { email, otp } = req.body;

        // Find the user by email in the database
        let isUserExists = await User.findOne({ email: email });

        // If user exists
        if (isUserExists) {
            let isVerified = isUserExists.isVerified;
            // If user is not already verified
            if (isVerified !== true) {
                let code = isUserExists.code;
                // If the entered OTP matches the stored code
                if (code == otp) {
                    // Update user's verification status to true
                    const filter = { email: email };
                    const update = {
                        $set: {
                            isVerified: true
                        },
                    };
                    const check = await User.updateOne(filter, update);
                    // Return a success response
                    return res.status(200).send({
                        status: true,
                        msg: Msg.otpVerified,
                    })
                } else {
                    // If the entered OTP is wrong, return an error response
                    return res.status(200).send({
                        status: true,
                        msg: Msg.wrongOtp,
                    })
                }
            } else {
                // If the user is already verified, return a response indicating that
                return res.status(200).send({
                    status: true,
                    msg: Msg.allReadyOtpVerified,
                })
            }
        } else {
            // If user does not exist, return a response indicating that
            return res.status(200).send({
                status: true,
                msg: Msg.dataNotFound
            })
        }
    } catch (error) {
        // If an error occurs during OTP verification process, return a server error response
        return res.status(500).send({
            status: false,
            msg: Msg.err
        })
    }
}

// Function to resend OTP for user verification
exports.resendOtpfn = async (req, res) => {
    try {
        let { email } = req.body; // Extract email from request body

        // Check if the user exists with the provided email
        let isUserExists = await User.findOne({ email: email });

        // If user exists
        if (isUserExists) {
            let id = isUserExists._id; // Get the user's ID
            const randomNumber = await generateRandomNumber(10000, 20000); // Generate a new random OTP
            const filter = { _id: id }; // Define the filter to find the user

            // Define the update operation to set the new OTP
            const update = {
                $set: {
                    code: randomNumber
                },
            };

            // Update the user's OTP in the database
            const check = await User.updateOne(filter, update);

            // If OTP update is successful
            if (check && check !== null) {
                // Send the new OTP via email
                await sendMail.mail(email, randomNumber);
                return res.status(200).send({
                    status: true,
                    msg: Msg.otpSend, // Send success message
                });
            } else {
                return res.status(200).send({
                    status: true,
                    msg: Msg.otpNotSend, // Send error message if OTP update fails
                });
            }
        } else {
            // If user does not exist with the provided email
            return res.status(200).send({
                status: true,
                msg: Msg.dataNotFound, // Send message indicating data not found
            });
        }
    } catch (error) {
        // If an error occurs during OTP resend process, return a server error response
        return res.status(500).send({
            status: false,
            msg: Msg.err, // Send error message
        });
    }
}

// Function to handle user login
exports.userLogin = async (req, res) => {
    try {
        let { email, password } = req.body; // Extract email and password from request body

        // Find the user by email in the database
        let isUserExists = await User.findOne({ email: email });

        // If user exists and is not null
        if (isUserExists && isUserExists !== null) {
            let pass = isUserExists.password; // Get the user's hashed password
            let checkPassword = await bcrypt.compare(password, pass); // Compare entered password with hashed password

            // If passwords match
            if (checkPassword) {
                const payload = { userId: isUserExists._id }; // Create payload for JWT token
                const token = jwt.sign(payload, secretKey, { expiresIn: '1h' }); // Generate JWT token with expiration time

                return res.status(200).send({
                    status: true,
                    msg: Msg.userLoggedIn, // Send success message
                    token: token // Send JWT token
                });
            } else {
                return res.status(200).send({
                    status: false,
                    msg: Msg.inValidPassword, // Send error message if password is invalid
                });
            }
        } else {
            return res.status(200).send({
                status: false,
                msg: Msg.inValidEmail, // Send error message if user does not exist with provided email
            });
        }
    } catch (error) {
        // If an error occurs during login process, return a server error response
        return res.status(500).send({
            status: false,
            msg: Msg.err, // Send error message
        });
    }
}


// Function to change user password
exports.changePassword = async (req, res) => {
    try {
        let userId = req.decoded.userId; // Get the user ID from the decoded JWT token
        let { old_password, new_password } = req.body; // Extract old and new passwords from request body

        // Find the user by ID in the database
        let isUserExists = await User.findOne({ _id: userId });

        // If user exists and is not null
        if (isUserExists && isUserExists !== null) {
            let getOldPassword = isUserExists.password; // Get the user's hashed old password
            let checkPassword = await bcrypt.compare(old_password, getOldPassword); // Compare entered old password with hashed old password

            // If old password matches
            if (checkPassword) {
                let newPassword = await hashPassword(new_password); // Hash the new password

                // Define filter to find the user by ID and update operation to set the new password
                const filter = { _id: userId };
                const update = {
                    $set: {
                        password: newPassword
                    },
                };

                // Update user's password in the database
                const check = await User.updateOne(filter, update);

                // If password update is successful, return success response
                if (check) {
                    return res.status(200).send({
                        status: true,
                        msg: "Password Change Successfully",
                    });
                } else {
                    // If password update fails, return error response
                    return res.status(200).send({
                        status: true,
                        msg: "Password not Change",
                    });
                }
            } else {
                // If old password does not match, return error response
                return res.status(200).send({
                    status: false,
                    msg: "Invalid password",
                });
            }
        } else {
            // If user does not exist with the provided ID, return error response
            return res.status(200).send({
                status: false,
                msg: "User Not Exists",
            });
        }
    } catch (error) {
        // If an error occurs during password change process, return a server error response
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}

// Function to send OTP for password reset
exports.forgetPasswordSendOtpFn = async (req, res) => {
    try {
        let { email } = req.body; // Extract email from request body

        // Find the user by email in the database
        let isUserExists = await User.findOne({ email: email });

        // If user exists with the provided email
        if (isUserExists) {
            const randomNumber = await generateRandomNumber(10000, 20000); // Generate a random OTP
            const filter = { email: email }; // Define filter to find the user by email

            // Define update operation to set the new OTP
            const update = {
                $set: {
                    code: randomNumber
                },
            };

            // Update user's OTP in the database
            const check = await User.updateOne(filter, update);

            // If OTP update is successful
            if (check) {
                // Send the OTP via email
                let emailSendFunction = await sendMail.mail(email, randomNumber);
                return res.status(200).send({
                    status: true,
                    msg: "otp send successfully",
                });
            }
        } else {
            // If user does not exist with the provided email, return error response
            return res.status(200).send({
                status: true,
                msg: "user not found"
            });
        }
    } catch (error) {
        // If an error occurs during OTP sending process, return a server error response
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}


// Function to reset user password using OTP verification
exports.forgetPasswordFn = async (req, res) => {
    try {
        let { email, otp, password } = req.body; // Extract email, OTP, and new password from request body

        // Find the user by email in the database
        let isUserExists = await User.findOne({ email: email });

        // If user exists with the provided email
        if (isUserExists) {
            let code = isUserExists.code; // Get the stored OTP for the user
            // If the provided OTP matches the stored OTP
            if (code == otp) {
                let newPassword = await hashPassword(password); // Hash the new password

                // Define filter to find the user by email and update operation to set the new password
                const filter = { email: email };
                const update = {
                    $set: {
                        password: newPassword
                    },
                };

                // Update user's password in the database
                const check = await User.updateOne(filter, update);

                // If password update is successful, return success response
                if (check) {
                    return res.status(200).send({
                        status: true,
                        msg: "Your Password Has Been Reset Successfully",
                    });
                } else {
                    // If password update fails, return error response
                    return res.status(200).send({
                        status: true,
                        msg: "Your Password Could Not Be Reset",
                    });
                }
            } else {
                // If OTP is invalid, return error response
                return res.status(200).send({
                    status: true,
                    msg: "Invalid OTP",
                });
            }
        } else {
            // If user does not exist with the provided email, return error response
            return res.status(200).send({
                status: true,
                msg: "User not found"
            });
        }
    } catch (error) {
        // If an error occurs during password reset process, return a server error response
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}

// Function to get user profile
exports.getUserProfileFn = async (req, res) => {
    try {
        let userId = req.decoded.userId; // Get the user ID from the decoded JWT token

        // Find the user by ID in the database
        let isUserExists = await User.findOne({ _id: userId });

        // If user exists and is not null, return user profile
        if (isUserExists && isUserExists !== null) {
            return res.status(200).send({
                status: true,
                msg: "User Found Successfully",
                data: isUserExists // Send user profile data
            });
        } else {
            // If user does not exist with the provided ID, return error response
            return res.status(200).send({
                status: false,
                msg: "User Not Exists",
                data: [] // Send empty data
            });
        }
    } catch (error) {
        // If an error occurs while getting user profile, return a server error response
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}

// Function to update user profile
exports.updateUserProfileFn = async (req, res) => {
    try {
        let userId = req.decoded.userId; // Get the user ID from the decoded JWT token
        let { name, number, email, address } = req.body; // Extract updated user profile fields from request body

        // Define filter to find the user by ID and update operation to set the updated profile fields
        const filter = { _id: userId };
        const update = {
            $set: {
                name: name,
                phone: number,
                email: email,
                address: address
            },
        };

        // Update user's profile in the database
        let check = await User.findByIdAndUpdate(filter, update, { new: true });

        // If profile update is successful, return success response
        if (check) {
            return res.status(200).send({
                status: true,
                msg: "User profile updated successfully"
            });
        } else {
            // If profile update fails, return error response
            return res.status(200).send({
                status: true,
                msg: "User profile not updated"
            });
        }
    } catch (error) {
        // If an error occurs during profile update process, return a server error response
        return res.status(500).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}




