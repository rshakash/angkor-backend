const express = require('express');
const passport = require('passport');
const app = express();
const cors = require('cors');
const session = require('express-session');
const {pool} = require('./dbConfig');
const bcrypt = require('bcrypt');
const crops = require('./crops.json');

const initializePassport = require('./passportConfig');
initializePassport(passport);

const PORT = process.env.PORT || 3000;
app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());

const checkAuthenticated = (req, res, next) => {
    if(req.isAuthenticated()) {
        return res.redirect('http://localhost:5173');
    }
    next();
}

const checkNotAuthenticated = (req, res, next) => {
    if(req.isAuthenticated()) {
        return next();
    }
    res.redirect('http://localhost:5173/login');
}

app.post("/register", async (req, res) => {
    let { name, email, password, confirmpassword, username, role} = req.body;
    console.log(name, email, password, confirmpassword, username, role);

    let errors = [];
    if(!name || !email || !password || !confirmpassword || !username || !role){
        errors.push({message: "Please enter all fields"});
    }
    if(password.length < 8){
        errors.push({message: "Password should be atleast 8 characters long"});
    }
    if(password !== confirmpassword){
        errors.push({message: "Passwords do not match"});
    }
    if(errors.length > 0){
        res.json({errors});
    }else{
        let hashedPassword = await bcrypt.hash(password, 10);
        pool.query(
            `SELECT * FROM users
            WHERE email = $1`, [email], (err, results) => {
                if(err){
                    throw err;
                }
                if(results.rows.length > 0){
                    errors.push({message: "Email already registered"});
                    res.json({errors});
                }else{
                    pool.query(
                        `SELECT * FROM users WHERE username = $1`, [username], (err, results) => {
                            if(err){
                                throw err;
                            }
                            if(results.rows.length > 0){
                                errors.push({message: "Username already registered"});
                                res.json({errors});
                            }else{
                                pool.query(
                                    `INSERT INTO users (name, email, password, username, role)
                                    VALUES ($1, $2, $3, $4, $5)
                                    RETURNING id, password`, [name, email, hashedPassword, username, role], (err, results) => {
                                        if(err){
                                            throw err;
                                        }
                                        console.log(results.rows);
                                        res.json({message: "User registered successfully"});
                                    }
                                )
                            }
                        }
                    )
                }
            }
        )
    }
});

app.get("/logout", (req, res) => {
    req.logOut(err => {
        if(err){
            throw(err);
        }else{
            res.redirect("http://localhost:5173/login")
        }
    })
})

app.post('/login', 
passport.authenticate('local'), (req, res) => {
    res.json({user: req.user})
})


app.get('/api/crops', (req, res) => {
    res.json(crops);
});


app.listen(3000, () => {
    console.log('Server is running on port 3000');
});