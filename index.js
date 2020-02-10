const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session')
const MongoStore = require('connect-mongo')(session);
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require("express-rate-limit");
const cors = require('cors')
const https = require('https');
const path = require('path');
const bcrypt = require('bcrypt');
const {check,validationResult} = require('express-validator');
var transporter = nodemailer.createTransport({
 service: 'gmail',
 auth: {
        user: 'auth.test.reg.email@gmail.com',
        pass: 'password'
    }
});


const SALTROUNDS = 10;
const PASS_MIN=8;
const PASS_MAX=128;
var MongoClient = require('mongodb').MongoClient;
var url = 'mongodb://localhost/';
var options = {
    useNewUrlParser: true,
    useUnifiedTopology: true
};
const db_main = 'user_data';
const client = new MongoClient(url, options);
client.connect(function(err) {
    if (err) {
        console.log(err)
    } else {
        console.log("Connected successfully to db server");
    }
});
client.db(db_main).listCollections({
    name: "not_activated_users"
}).toArray().then(function(items) {
    if (items.length === 0) {
        client.db(db_main).collection("not_activated_users").createIndex({
            "createdAt": 1
        }, {
            expireAfterSeconds: 86400
        });
    }
});

client.db(db_main).listCollections({
    name: "password_recovery"
}).toArray().then(function(items) {
    if (items.length === 0) {
        client.db(db_main).collection("password_recovery").createIndex({
            "createdAt": 1
        }, {
            expireAfterSeconds: 86400
        });
    }
});
const app = express();
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', "nosniff")
  res.setHeader('X-Frame-Options', "Deny")  //clickjacking protection
  next();
});

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());
app.use(cors());
app.disable('x-powered-by');
app.use(cookieParser());
app.use(session({
    secret: 'ghuieorifigyfuu9u3i45jtr73490548t7ht',
    resave: false,
    saveUninitialized: true,
    name: "session",
    cookie: {
        maxAge: 14 * 24 * 60 * 60 * 1000
    },
    store: new MongoStore({
        url: 'mongodb://localhost/user_data',
        ttl: 14 * 24 * 60 * 60
    }) // = 14 days. Default 
}))

const port = 80;
app.listen(port, () => { //Uncomment if you want to use http
    console.log(`Server is listening on port ${port}`);
});
var Recaptcha = require('express-recaptcha').RecaptchaV3;
var recaptcha = new Recaptcha('6LcqV9QUAAAAAEybBVr0FWnUnFQmOVxGoQ_Muhtb', '6LcqV9QUAAAAAOA18kbCEWRBhF4g4LjSTaFRVe9P');


//  https.createServer({
//       key: fs.readFileSync('privkey.pem'),
//       cert: fs.readFileSync('cert.pem')
//     }, app).listen(port);

// console.log(`Server is listening on port ${port}`);

function send_activation_letter(email, link) {
    const mailOptions = {
        from: 'auth.test.reg.email@gmail.com', // sender address
        to: email, // list of receivers
        subject: 'Confirmation link', // Subject line
        html: `<p>Your confirmation link ${link} If it was not you, ignore this email.</p>` // plain text body
    };
    transporter.sendMail(mailOptions, function(err, info) {
        if (err) {
            console.log(err)
        } else {
            console.log(info);
        }
    });
}

function send_forgot_password_letter(email, link) {
    const mailOptions = {
        from: 'auth.test.reg.email@gmail.com', // sender address
        to: email, // list of receivers
        subject: 'Restore password link', // Subject line
        html: `<p>Your link to restore your password ${link} If it was not you, ignore this email.</p>` // plain text body
    };
    transporter.sendMail(mailOptions, function(err, info) {
        if (err) {
            console.log(err)
        } else {
            console.log(info);
        }
    });
}


async function generate_id() {
    const id = new Promise((resolve, reject) => {
        crypto.randomBytes(32, async function(ex, buffer) {
            if (ex) {
                reject("error");
            }
            let id = buffer.toString("base64")
            let users = await find_user_by_id(id) //check if id exists
            if (users.length === 0) {
                resolve(id);
            } else {
                let id_1 = await generate_id()
                resolve(id_1)
            }
        });
    });
    return id;
}


async function generate_activation_token() {
    const token = new Promise((resolve, reject) => {
        crypto.randomBytes(16, async function(ex, buffer) {
            if (ex) {
                reject("error");
            }
            let token = buffer.toString("base64").replace(/\/|=|[+]/g, '')
            let users = await find_not_activated_user_by_token(token) //check if token exists
            if (users.length === 0) {
                resolve(token);
            } else {
                let token_1 = await generate_activation_token()
                resolve(token_1)
            }
        });
    });
    return token;
}

async function generate_password_recovery_token() {
    const token = new Promise((resolve, reject) => {
        crypto.randomBytes(16, async function(ex, buffer) {
            if (ex) {
                reject("error");
            }
            let token = buffer.toString("base64").replace(/\/|=|[+]/g, '')
            let user_id = await find_user_id_by_password_recovery_token(token) //check if token exists
            if (user_id.length === 0) {
                resolve(token);
            } else {
                let token_1 = await generate_password_recovery_token()
                resolve(token_1)
            }
        });
    });
    return token;
}


async function findDocuments(collection_name, selector) {
    const collection = client.db(db_main).collection(collection_name);
    let result = await collection.find(selector).toArray()
    return result
}
async function removeDocument(collection_name, selector) {
    const collection = client.db(db_main).collection(collection_name);
    collection.deleteOne(selector)
}

async function insertDocuments(collection_name, documents) {
    const collection = client.db(db_main).collection(collection_name);
    let result = await collection.insertMany(documents);
    // return result
}
async function updateDocument(collection_name,selector,update) {
  const collection = client.db(db_main).collection(collection_name);
  let result= await collection.updateOne(selector, { $set: update })

}



////////////////////////////////////////PASSWORD RECOVERY
async function update_user_password_by_id(id,password) {
    updateDocument("users", {id: id},{password:password})
}

async function delete_password_recovery_token(token) {
    removeDocument("password_recovery", {
        token: token
    })
}

async function save_password_recovery_token(token, user_id) {
    insertDocuments("password_recovery", [{
        "createdAt": new Date(),
        token: token,
        user_id: user_id,
    }])
}

async function find_user_id_by_password_recovery_token(token) {
    let user = await findDocuments("password_recovery", {
        token: token
    })
    return user
}
//////////////////////////////////////////

//////////////////////////////////////////ACTIVATED USER
async function find_user_by_email(email) {
    let user = await findDocuments("users", {
        email: email
    })
    return user
}

async function find_user_by_id(id) {
    let user = await findDocuments("users", {
        id: id
    })
    return user
}

async function create_new_user_activated(email, pass) {
    insertDocuments("users", [{
        email: email,
        id: await generate_id(),
        password: pass,
        activated: true
    }])
}
/////////////////////////////////////////////////////////


//////////////////////////////////////////NOT ACTIVATED USER
async function find_not_activated_user_by_token(token) {
    let user = await findDocuments("not_activated_users", {
        token: token
    })
    return user
}

async function delete_not_activated_user_by_token(token) {
    removeDocument("not_activated_users", {
        token: token
    })
}

async function create_new_user_not_activated(email, pass, token) {
    insertDocuments("not_activated_users", [{
        "createdAt": new Date(),
        email: email,
        token: token,
        password: pass,
        activated: false
    }])
}
/////////////////////////////////////////////////////////



app.get('/', (req, res) => {
    if (req.session.authed !== undefined) {
        res.send('<p>You are logged in!</p>')
    } else {
        res.redirect('/login')
    }

})
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'))
})
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'))
})
app.get('/forgot_password', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot_password.html'))
})
app.get('/change_password', (req, res) => {
    res.sendFile(path.join(__dirname, 'change_password.html'))
})

app.post('/signup', [
    recaptcha.middleware.verify,
    check('email').isEmail(),
    check('password').isLength({
        min: PASS_MIN,
        max: PASS_MAX
    })
], async (req, res) => {
    if (req.recaptcha.error) {
     return res.status(403).json({message: ["Captcha error"]})
    } 
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            message: errors.array()
        });
    }
    var email = req.body.email;
    var password = req.body.password
    var users = await find_user_by_email(email);
    if (users.length === 0) { //if no user with this email is registered
       var token=await generate_activation_token()    //always unique
       let hashed_pass = await bcrypt.hash(password, SALTROUNDS);
       create_new_user_not_activated(email, hashed_pass, token)
       var link = `http://localhost/activate?token=${token}`
       console.log(link)
       send_activation_letter(email, link)
       res.json({
           message: 'Registered successfully,please confirm your email.'
       })
    } else {
        console.log(users)
        res.json({
            message: 'User with same email is already registered'
        })
    }
})

app.post('/login', [
    recaptcha.middleware.verify,
    check('email').isEmail(),
    check('password').isLength({
        min: PASS_MIN,
        max: PASS_MAX
    }),
], async (req, res) => {
    if (req.recaptcha.error) {
     return res.status(403).json({message: ["Captcha error"]});
    } 
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            message: errors.array()
        });
    }

    const MESSAGE_FOR_AUTH_ERROR = "This combination of email and password is not found";
    var email = req.body.email;
    var password = req.body.password
    var users = await find_user_by_email(email);
    if (users.length === 0) {
        res.json({
            message: MESSAGE_FOR_AUTH_ERROR
        })
    } else {
        const match = await bcrypt.compare(password, users[0].password);
        if (match) {
            if (users[0].activated === true) {
                req.session.authed = true;
                req.session.user_id = users[0].id;
                res.json({
                    message: "Success"
                })
            } else {
                res.json({
                    message: "Please confirm your email"
                })
            }
        } else {
            res.json({
                message: MESSAGE_FOR_AUTH_ERROR
            })
        }
    }
})


app.post('/change_pw', [
    recaptcha.middleware.verify,
    check('password').isLength({
        min: PASS_MIN,
        max: PASS_MAX
    }),
], async (req, res) => {
    if (req.recaptcha.error) {
     return res.status(403).json({message: ["Captcha error"]});
    } 
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            message: errors.array()
        });
    }
    const MESSAGE_FAIL = "Your link is expired or wrong";
    const MESSAGE_SUCCESS = "Password is successfully changed. Now you can log in using new password.";
    var token = req.body.token
    var password = req.body.password
    var obj = await find_user_id_by_password_recovery_token(token);
    if (obj.length !== 0) { //IF password recovery token exists
        var user_id = obj[0].user_id
        var users = await find_user_by_id(user_id)
        if (users.length !== 0) {  //IF user exists
            let hashed_pass = await bcrypt.hash(password, SALTROUNDS);
            update_user_password_by_id(user_id, hashed_pass)
            delete_password_recovery_token(token)
            return res.json({message: MESSAGE_SUCCESS})
        }
    }
    res.json({message: MESSAGE_FAIL})
})

app.post('/forgot_pw', [
    recaptcha.middleware.verify,
    check('email').isEmail(),
], async (req, res) => {
    if (req.recaptcha.error) {
     return res.status(403).json({message: ["Captcha error"]});
    } 
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            message: errors.array()
        });
    }
    const MESSAGE_SUCCESS = "Link for password recovery has been sent, check your email.";
    var email = req.body.email;
    var users = await find_user_by_email(email);
    if (users.length === 1) {
        let token=await generate_password_recovery_token()
        let user_id=users[0].id
        save_password_recovery_token(token, user_id)
        let link = `http://localhost/change_password?token=${token}`
        send_forgot_password_letter(email,link)
    }
    return res.json({ message: MESSAGE_SUCCESS})           //Always returns success even if email doesn`t exitsts
})

app.get('/activate', async (req, res) => {
    var token = req.query.token;
    console.log(token)
    if (typeof token == 'string' || token instanceof String) {
        var users = await find_not_activated_user_by_token(token);
        if (users.length === 1) {
            delete_not_activated_user_by_token(token) //remove temp account
            create_new_user_activated(users[0].email, users[0].password)
            return res.send('<p>Your account is now activated. Visit <a href="http://localhost/login">http://localhost/login</a> to login in.</p>')
        }
    }
    res.send('<p>Activation link is wrong</p>')
})

app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(function(err) {
            if (err) {
                res.send('<p>error</p>')
            } else {
                res.send('<p>logout successful</p>')
            }
        });
    }
})