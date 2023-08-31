const router = require('express').Router();
const user_util = require('../util/user_util');
const { isAlumni, isStudent, isHR, isAuthorized, isAlumniOrStudent, isProfessor } = require('../middlewares/Auth');
const path = require('path');
const { sendEmail } = require('../util/mail_util');
const { FRONTEND_URL, CLOUDINARY_API_SECRET } = require('../config/config');
const cloudinary = require('cloudinary').v2;
cloudinary.config({
    cloud_name: 'do6oz83pz',
    api_key: '524566722143567',
    api_secret: CLOUDINARY_API_SECRET,
    upload_preset: 'ggdkuker'
});


router.post('/alumni_signup', async (req, res, next) => {
    try {
        const { UserName, Password, Email, National_Id } = req.body;
        if (!UserName || !Password || !Email || !National_Id) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        if (await user_util.checkEmailExists(Email) || await user_util.checkNationalIdExists(National_Id) || await user_util.checkUserNameExists(UserName)) {
            res.status(400).send({ success: false, message: 'Email or National Id or User Name already exists.' });
            return;
        }
        await user_util.addAlumni({ UserName, Password, Email, National_Id });
        res.status(201).send({ success: true, message: 'Alumni added successfully.' });
    } catch (err) {
        next(err);
    }
});

router.post('/alumni_login', async (req, res, next) => {
    try {
        const { UserName, Password } = req.body;
        if (!UserName || !Password) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
        }
        const alumni = await user_util.getAlumni(UserName);
        if (!alumni) {
            res.status(404).send({ success: false, message: 'Alumni not found.' });
        } else {
            const isMatch = await user_util.comparePassword(Password, alumni.Password);
            if (!isMatch) {
                res.status(401).send({ success: false, message: 'Invalid credentials.' });
            } else {
                req.session.RoleName = "Alumni";
                req.session.IsLoggedIn = true;
                req.session.User_Id = alumni.User_Id;
                req.session.UserName = alumni.UserName;
                res.status(200).send({
                    success: true,
                    actor: "Alumni",
                    user_id: alumni.User_Id,
                    user_name: alumni.UserName,
                    message: 'Alumni logged in successfully.'
                });
            }
        }
    } catch (err) {
        next(err);
    }
});

router.get('/alumni_logout', isAlumni, (req, res, next) => {
    try {
        req.session.destroy();
        res.clearCookie('connect.sid');
        res.status(200).send({ success: true, message: 'Alumni logged out successfully.' });
    } catch (err) {
        next(err);
    }
});

router.put('/update_phone', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        const { Phone } = req.body;
        if (!Phone) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        await user_util.updatePhone(User_Id, Phone);
        res.status(200).send({ success: true, message: 'Phone updated successfully.' });
    } catch (err) {
        if (err.message === 'Phone already exists') {
            res.status(409).send({ success: false, message: 'Phone already exists.' });
            return;
        }
        next(err);
    }
});

router.post('/check_national_id', async (req, res, next) => {
    try {
        const { NID } = req.body;
        if (!NID) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        const exists = await user_util.checkNationalIdExists(NID);
        if (exists) {
            res.status(200).send({ success: false, message: 'National Id exists please try another one..' });
        }
        else {
            res.status(404).send({ success: true, message: 'National Id does not exist.' });
        }
    } catch (err) {
        next(err);
    }
});

router.post('/check_email', async (req, res, next) => {
    try {
        const { Email } = req.body;
        if (!Email) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        const exists = await user_util.checkEmailExists(Email);
        if (exists) {
            res.status(200).send({ success: false, message: 'Email already exists please try another one.' });
        }
        else {
            res.status(404).send({ success: true, message: 'Email does not exist.' });
        }
    } catch (err) {
        next(err);
    }
});

router.post('/check_user_name', async (req, res, next) => {
    try {
        const { UserName } = req.body;
        if (!UserName) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        const exists = await user_util.checkUserNameExists(UserName);
        if (exists) {
            res.status(200).send({ success: false, message: 'User Name exists please try another one..' });
        }
        else {
            res.status(200).send({ success: true, message: 'User Name does not exist.' });
        }
    } catch (err) {
        next(err);
    }
});

router.post("/check_academic_id", async (req, res, next) => {
    try {
        const { Academic_Id } = req.body;
        if (!Academic_Id) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        const exists = await user_util.checkAcademicIdExists(Academic_Id);
        if (exists) {
            res.status(200).send({ success: false, message: 'Academic Id exists please try another one..' });
        }
        else {
            res.status(200).send({ success: true, message: 'Academic Id does not exist.' });
        }
    } catch (err) {
        next(err);
    }
});


// check if user is logged in
router.get('/is_logged_in', isAuthorized, (req, res, next) => {
    try {
        const actor = req.session.RoleName;
        res.status(200).send({ success: true, message: 'User is logged in.', actor });
    } catch (err) {
        next(err);
    }
});

router.get('/get_alumni', isAlumni, async (req, res, next) => {
    try {
        const { UserName } = req.session;
        const alumni = await user_util.getAlumni(UserName);
        if (!alumni) {
            res.status(404).send({ success: false, message: 'Alumni not found.' });
            return;
        }
        res.status(200).send({ success: true, alumni });
    } catch (err) {
        next(err);
    }
});

router.post('/student_signup', async (req, res, next) => {
    try {
        const { UserName, Password, Email, National_Id, Academic_Id } = req.body;
        if (!UserName || !Password || !Email || !National_Id || !Academic_Id) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        if (await user_util.checkEmailExists(Email) || await user_util.checkNationalIdExists(National_Id) || await user_util.checkUserNameExists(UserName)) {
            res.status(400).send({ success: false, message: 'Email or National Id or User Name already exists.' });
            return;
        }
        await user_util.addStudent({ UserName, Password, Email, National_Id, Academic_Id });
        res.status(201).send({ success: true, message: 'Student added successfully.' });
    } catch (err) {
        next(err);
    }
});

router.post('/student_login', async (req, res, next) => {
    try {
        const { UserName, Password } = req.body;
        if (!UserName || !Password) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
        }
        const student = await user_util.getStudent(UserName);
        if (!student) {
            res.status(404).send({ success: false, message: 'Student not found.' });
        } else {
            const isMatch = await user_util.comparePassword(Password, student.Password);
            if (!isMatch) {
                res.status(401).send({ success: false, message: 'Invalid credentials.' });
            } else {
                req.session.RoleName = "Student";
                req.session.IsLoggedIn = true;
                req.session.User_Id = student.User_Id;
                req.session.UserName = student.UserName;
                res.status(200).send({
                    success: true,
                    actor: "Student",
                    user_id: student.User_Id,
                    user_name: student.UserName,
                    message: 'Student logged in successfully.'
                });
            }
        }
    } catch (err) {
        next(err);
    }
});

router.get('/student_logout', isStudent, (req, res, next) => {
    try {
        req.session.destroy();
        res.clearCookie('connect.sid');
        res.status(200).send({ success: true, message: 'Student logged out successfully.' });
    } catch (err) {
        next(err);
    }
});

router.get("/logout", isAuthorized, (req, res, next) => {
    try {
        req.session.destroy();
        res.clearCookie('connect.sid');
        const sessionId = req.body.sessionId;
        // destroy session
        req.sessionStore.destroy(sessionId, (err) => {
            if (err) {
                console.error("session err", err);
                res.status(500).send({ success: false, message: 'Internal Server Error.' });
            } else {
                res.status(200).send({ success: true, message: 'User logged out successfully.' });
            }
        });
    } catch (err) {
        next(err);
    }
});

router.get('/get_student', isStudent, async (req, res, next) => {
    try {
        const { UserName } = req.session;
        const student = await user_util.getStudent(UserName);
        if (!student) {
            res.status(404).send({ success: false, message: 'Student not found.' });
            return;
        }
        res.status(200).send({ success: true, student });
    } catch (err) {
        next(err);
    }
});

router.post("/hr_signup", async (req, res, next) => {
    try {
        const { UserName, Password, Email, LastName, FirstName } = req.body;
        if (!UserName || !Password || !Email || !FirstName || !LastName) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        if (await user_util.checkEmailExists(Email) || await user_util.checkUserNameExists(UserName)) {
            res.status(400).send({ success: false, message: 'Email or National Id or User Name already exists.' });
            return;
        }
        await user_util.addHR({ UserName, Password, Email, FirstName, LastName });
        res.status(201).send({ success: true, message: 'HR added successfully.' });
    } catch (err) {
        next(err);
    }
});

router.post('/hr_login', async (req, res, next) => {
    try {
        const { UserName, Password } = req.body;
        if (!UserName || !Password) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
        }
        const hr = await user_util.getHR(UserName);
        if (!hr) {
            res.status(404).send({ success: false, message: 'HR not found.' });
        } else {
            const isMatch = await user_util.comparePassword(Password, hr.Password);
            if (!isMatch) {
                res.status(401).send({ success: false, message: 'Invalid credentials.' });
            } else {
                req.session.RoleName = "HR";
                req.session.IsLoggedIn = true;
                req.session.User_Id = hr.User_Id;
                req.session.UserName = hr.UserName;
                res.status(200).send({
                    success: true,
                    actor: "HR",
                    user_id: hr.User_Id,
                    user_name: hr.UserName,
                    message: 'HR logged in successfully.'
                });
            }
        }
    } catch (err) {
        next(err);
    }
});

router.get('/hr_logout', isHR, (req, res, next) => {
    try {
        req.session.destroy();
        res.clearCookie('connect.sid');
        res.status(200).send({ success: true, message: 'HR logged out successfully.' });
    } catch (err) {
        next(err);
    }
});

// upload picture
router.post('/upload_picture', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id, UserName } = req.session;
        const { pictureUrl } = req.body;
        const user = await user_util.getUser(UserName);
        if (!user) {
            res.status(404).send({ success: false, message: 'User not found.' });
            return;
        }
        // delete old picture from cloudinary if exists
        if (user.Img) {
            const public_id = "images/" + user.Img.split('/').slice(-1)[0].split('.')[0];
            await cloudinary.uploader.destroy(public_id);
        }
        await user_util.uploadPicture(User_Id, pictureUrl);
        res.status(200).send({ success: true, message: 'Picture uploaded successfully.', Img: pictureUrl })
    } catch (err) {
        next(err);
    }
});



router.post('/upload_cv', isAlumniOrStudent, async (req, res, next) => {
    try {
        const { User_Id, UserName } = req.session;
        const { cvUrl } = req.body;
        if (!cvUrl) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        const user = await user_util.getUser(UserName);
        if (!user) {
            res.status(404).send({ success: false, message: 'User not found.' });
            return;
        }
        // delete old cv from cloudinary if exists
        if (user.CV) {
            const public_id = "cvs/" + user.CV.split('/').slice(-1)[0].split('.')[0];
            await cloudinary.uploader.destroy(public_id);
        }
        await user_util.uploadCV(User_Id, cvUrl);
        res.status(200).send({ success: true, message: 'CV uploaded successfully.', CV: cvUrl }).end();
    } catch (err) {
        next(err);
    }
});


router.put('/update_about', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        const { About } = req.body;
        if (!About) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        await user_util.updateAbout(User_Id, About);
        res.status(200).send({ success: true, message: 'About updated successfully.' });
    } catch (err) {
        next(err);
    }
});

router.put('/update_country', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        const { Country } = req.body;
        if (!Country) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        await user_util.updateCountry(User_Id, Country);
        res.status(200).send({ success: true, message: 'Country updated successfully.' });
    } catch (err) {
        next(err);
    }
});


router.put('/update_social_urls', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        const { Behance_URL, LinkedIn_URL, GitHub_URL } = req.body;
        let data = {};
        if (Behance_URL) {
            data.Behance_URL = Behance_URL;
        }
        if (LinkedIn_URL) {
            data.LinkedIn_URL = LinkedIn_URL;
        }
        if (GitHub_URL) {
            data.GitHub_URL = GitHub_URL;
        }
        if (Object.keys(data).length === 0) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        await user_util.updateSocialUrls(User_Id, data);
        res.status(200).send({ success: true, message: 'Social URLs updated successfully.' });
    } catch (err) {
        next(err);
    }
});

router.put('/update_name', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        const { FirstName, LastName } = req.body;
        if (!FirstName || !LastName) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
            return;
        }
        await user_util.updateName(User_Id, { FirstName, LastName });
        res.status(200).send({ success: true, message: 'Name updated successfully.' });
    } catch (err) {
        next(err);
    }
});


router.post("/login", async (req, res, next) => {
    try {
        const { UserName, Password } = req.body;
        if (!UserName || !Password) {
            res.status(400).send({ success: false, message: 'Missing credentials.' });
        }
        const user = await user_util.getUser(UserName);
        if (!user) {
            res.status(404).send({ success: false, message: 'User not found.' });
        } else {
            const isMatch = await user_util.comparePassword(Password, user.Password);
            if (!isMatch) {
                res.status(401).send({ success: false, message: 'Invalid credentials.' });
            } else {
                // console.log(user);
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
                    message: 'User logged in successfully.'
                });
            }
        }
    } catch (err) {
        next(err);
    }
});

router.get('/fetch_cookie', (req, res, next) => {
    try {
        // extract cookie from request
        console.log('Cookies: ')
        console.log(req.cookies);
        console.log('Signed Cookies: ', req.signedCookies)
        res.status(200).send({ success: true, message: 'Cookie fetched successfully.', cookie: req.cookies });
    } catch (err) {
        next(err);
    }
});

router.delete('/delete_profile_picture', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        await user_util.deleteProfilePicture(User_Id);
        res.status(200).send({ success: true, message: 'Profile picture deleted successfully.' });
    } catch (err) {
        next(err);
    }
});

router.delete('/delete_cv', isAlumniOrStudent, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        await user_util.deleteCV(User_Id);
        res.status(200).send({ success: true, message: 'CV deleted successfully.' });
    } catch (err) {
        next(err);
    }
});

router.delete('/delete_behance_url', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        await user_util.deleteBehance_URL(User_Id);
        res.status(200).send({ success: true, message: 'Behance URL deleted successfully.' });
    } catch (err) {
        next(err);
    }
});

router.delete('/delete_github_url', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        await user_util.deleteGitHub_URL(User_Id);
        res.status(200).send({ success: true, message: 'GitHub URL deleted successfully.' });
    } catch (err) {
        next(err);
    }
});

router.delete('/delete_linkedin_url', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        await user_util.deleteLinkedIn_URL(User_Id);
        res.status(200).send({ success: true, message: 'LinkedIn URL deleted successfully.' });
    } catch (err) {
        next(err);
    }
});

router.delete('/delete_about', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        await user_util.deleteAbout(User_Id);
        res.status(200).send({ success: true, message: 'About deleted successfully.' });
    } catch (err) {
        next(err);
    }
});

router.delete('/delete_phone', isAuthorized, async (req, res, next) => {
    try {
        const { User_Id } = req.session;
        await user_util.deletePhone(User_Id);
        res.status(200).send({ success: true, message: 'Phone deleted successfully.' });
    } catch (err) {
        next(err);
    }
});

router.get('/', isAuthorized, async (req, res, next) => {
    try {
        const { UserName } = req.session;
        const user = await user_util.getUser(UserName);
        if (!user) {
            res.status(404).send({ success: false, message: 'User not found.' });
            return;
        }
        res.status(200).send({ success: true, user });
    } catch (err) {
        next(err);
    }
});

router.post('/reset_password', async (req, res, next) => {
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
        const url = `${FRONTEND_URL}${token}`;
        console.log(url);
        const reset_password_email = require('../mail_templates/reset_password.js')(url)
        const attachments = [{
            filename: 'vector.jpg',
            path: path.join(__dirname, '..', '..', 'public', 'static', 'vector.jpg'),
            cid: 'vector'
        }];
        sendEmail(email, 'Reset Password', '', reset_password_email, attachments);
    } catch (error) {
        console.log(error);
        next(error);
    }
});

router.post('/reset_password/:token', async (req, res, next) => {
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
        res.status(200).send({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
        next(error);
    }
});

module.exports = router;
