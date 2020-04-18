const express =  require('express');
const bcrypt = require('bcryptjs');
const jwt   = require('jsonwebtoken');
const passport = require('passport');

//validation
const validateRegisterInput = require('../../validations/register');

const router = express.Router();


const User = require('../../models/User');
const keys = require('../../config/keys');

router.post('/register', (req, res) => {
    const {errors, isValid} = validateRegisterInput(req.body);

    if (!isValid){
        return res.status(400).json(errors);
    }

    User.findOne({email: req.body.email})
        .then((user) => {
            if (user){
                return res.status(400).json({email: "Email Already Exist"});
            }else{
                const newUser = new User({
                    name:       req.body.name,
                    email:      req.body.email,
                    avatar:     req.body.avatar,
                    password:   req.body.password
                });

                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if (err) throw new Error(err);
                        newUser.password = hash;
                        newUser.save()
                            .then(response => res.json(response))
                            .catch(err => console.log(err))
                    })
                })
            }
        });
});

router.post('/login', (req, res) => {
    const email         =   req.body.email;
    const password      =   req.body.password;
    //check if email and password exist
    User.findOne({email: email})
        .then(user => {
            if (!user){
                return res.status(400).json({email: 'User not found'});
            }else{
                //check password
                bcrypt.compare(password, user.password)
                    .then(matched => {
                        if (matched){
                            //sign token
                            const payload = {id: user.id, name: user.name, avatar: user.avatar };
                            jwt.sign(payload, keys.secretOrKey, {expiresIn: 3600}, (err, token) =>{
                                res.json({
                                    success: true,
                                    token: `Bearer ${token}`
                                })
                            });
                        }else{
                            return res.status(400).json({password: 'password incorrect'});
                        }
                    })
            }
        })
});

//protected route
//returns authenticated user
router.get('/dashboard', passport.authenticate('jwt', {session: false}), (req, res) => {
    return res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email
    });
});


module.exports = router;
