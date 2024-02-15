const user_util = require('../utils/user_util');
const { ALUMNI_ROLE_ID, STUDENT_ROLE_ID, HR_ROLE_ID, ADMIN_ROLE_ID, PROFESSOR_ROLE_ID } = require('../utils/util');
const auth_util = require('../utils/auth_util');
const path = require('path');
const { sendEmail } = require('../services/Mail');
const { FRONTEND_URL } = require('../config/config');
const { validationResult } = require('express-validator');

function checkMissingFields(required) {
	missing_fields = [];
	for (const [key, value] of Object.entries(required)) {
		if (value === undefined || value === null || value === '') {
			missing_fields.push(key);
		}
	}
	return missing_fields;
}

/**
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function.
 * @description This function registers a user.
 * @async
 * @throws {Error} If there was an error registering the user.
 * @throws {Error} If the user is already registered.
 * @throws {Error} If the role is invalid.
 * @returns {Promise} A promise that resolves to the registered user.
 */
exports.register = async (req, res, next) => {
	try {
		if (!req.body) {
			res.status(400).json({ success: false, message: 'No data provided' });
			return;
		}
                const errors = validationResult(req)
                if (!errors.isEmpty()) {
                 return res.status(403).json({success: false ,message: 'Invalid data.' ,errors: errors.array()})
                }
                 
		const { UserName, Password, Email, Role_Id, Date_Of_Birth, FirstName, LastName } = req.body;
		const required = { UserName, Password, Email, Role_Id, Date_Of_Birth, FirstName, LastName };
		const missing_fields = checkMissingFields(required);
		if (missing_fields.length > 0) {
			res.status(400).json({ success: false, message: 'Missing credentials.', missing_fields });
			return;
		}
		// check if user already exists
		if ((await user_util.checkEmailExists(Email)) || (await user_util.checkUserNameExists(UserName))) {
			res.status(409).send({ success: false, message: 'User already exists.' });
			return;
		}
		// check if admin or professor if so forbid registration
		if (Role_Id === ADMIN_ROLE_ID || Role_Id === PROFESSOR_ROLE_ID) {
			res.status(403).json({ success: false, message: 'Forbidden.' });
			return;
		}
		const user = await auth_util.register(required);
		res.status(201).json({ success: true, message: 'User created successfully.', user });
	} catch (err) {
		next(err);
	}
};

exports.login = async (req, res, next) => {
	try {
		const { UserName, Password } = req.body;
		if (!UserName || !Password) {
			res.status(400).send({ success: false, message: 'Missing credentials.' });
			return;
		}
		const user = await auth_util.login(UserName, Password);
		req.session.RoleName = user.Role.Role_Name;
		req.session.IsLoggedIn = true;
		req.session.User_Id = user.User_Id;
		req.session.UserName = user.UserName;
		res.status(200).send({
			success: true,
			actor: user.Role.Role_Name,
			user_id: user.User_Id,
			user_name: user.UserName,
			sessionId: req.session.id,
			message: 'User logged in successfully.',
		});
	} catch (err) {
		if (err.message === 'User not found') {
			// user not found
			res.status(404).send({ success: false, message: 'User not found.' });
			return;
		} else if (err.message === 'Invalid credentials') {
			// invalid credentials
			res.status(401).send({ success: false, message: 'Invalid credentials.' });
			return;
		} else {
			// internal server error
			next(err);
		}
	}
};

exports.isLoggedIn = (req, res, next) => {
	try {
		const actor = req.body.session.RoleName;
		res.status(200).send({ success: true, message: 'User is logged in.', actor });
	} catch (err) {
		next(err);
	}
};

exports.logout = (req, res, next) => {
	try {
		req.session.destroy();
		res.clearCookie('connect.sid');
		const sessionId = req.body.sessionId;
		// destroy session
		req.sessionStore.destroy(sessionId, (err) => {
			if (err) {
				console.error('session err', err);
				res.status(500).send({ success: false, message: 'Internal Server Error.' });
			} else {
				res.status(200).send({ success: true, message: 'User logged out successfully.' });
			}
		});
	} catch (err) {
		next(err);
	}
};

exports.sendResetPasswordEmail = async (req, res, next) => {
	try {
		const { email } = req.body;
		if (!email) {
			res.status(400).send({ success: false, message: 'Missing credentials.' });
			return;
		}
		const user = await user_util.getUserByEmail(email);
		if (!user) {
			res.status(404).send({ success: false, message: 'User not found.' });
			return;
		}
		res.status(200).send({ success: true, message: 'Reset password email will be sent soon.' });
		const token = await user_util.generateResetPasswordToken(user);
		const url = `${FRONTEND_URL + 'resetPass/createNewPassword/'}${token}`;
		const reset_password_email = require('../mail_templates/reset_password.js')(url);
		await sendEmail(email, 'Reset Password', '', reset_password_email);
	} catch (error) {
		console.log(error);
		next(error);
	}
};

exports.changePassword = async (req, res, next) => {
	try {
		const { token } = req.params;
		const { password } = req.body;
		if (!password || !token) {
			res.status(400).send({ success: false, message: 'Missing credentials.' });
			return;
		}
		const user = await user_util.getUserByResetPasswordToken(token);
		if (!user) {
			res.status(404).send({ success: false, message: 'Invalid token' });
			return;
		}
		await user_util.updatePassword(user.User_Id, password);
		// look for all user sessions and destroy them
		res.status(200).send({ success: true, message: 'Password updated successfully.' });
		const sessions = await user_util.getUserSessions(user.User_Id);
		// console.log(sessions[0])
		if (sessions) {
			sessions.forEach((session) => {
				req.sessionStore.destroy(session.sid, (err) => {
					if (err) {
						console.error('session err', err);
					}
				});
			});
		}
	} catch (error) {
		next(error);
	}
};
