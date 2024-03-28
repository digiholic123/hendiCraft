// Import userController module
const userController = require('./userController');
// Import adminController module
const adminController = require('./adminController');

// Create an object to hold references to userController and adminController
const controller = {
    userController: userController, // Assign userController module to property userController
    adminController: adminController // Assign adminController module to property adminController
};

// Export the controller object to make it accessible from other files
module.exports = controller;  
