const validator =require('express-validator')


export const signupValidator = [
    validator.body('userName','must be string').not().isEmpty().isString(),
    validator.body('email', 'Invalid email').not().isEmpty().isEmail().matches(/^[\w]+@fci\.helwan\.edu\.eg$/),
    validator.body('password', 'Invalid password').not().isEmpty().isString().matches(/^[a-zA-Z0-9!@#$%^&*]{6,16}$/),
    validator.body('role_id', 'this field is required').not().isEmpty(),
    validator.body('DOB', 'this field is required').not().isEmpty(),
    validator.body('fName', 'minimum length is 3 characters ').isLength({min: 3}),
    validator.body('lName', 'minimum length is 3 characters').isLength({min: 3}),
  ]
