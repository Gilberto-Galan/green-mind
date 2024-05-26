const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path'); 

const app = express();

// Configuración de Express
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); 
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static('./public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

// Ruta para la página de inicio
app.get('/', (req, res) => {
    res.render('index'); // Renderiza la vista correspondiente a la página de inicio
});

// Ruta para la página "Acerca"
app.get('/nosotros', (req, res) => {
    res.render('nosotros'); // Renderiza la vista correspondiente a la página "Acerca"
});

// Ruta para la página "Cursos"
app.get('/cursos', (req, res) => {
    res.render('cursos'); // Renderiza la vista correspondiente a la página "Cursos"
});

// Ruta para la página "Tokens"
app.get('/tokens', (req, res) => {
    res.render('tokens'); // Renderiza la vista correspondiente a la página "Tokens"
});

// Ruta para la página "Perfil"
app.get('/perfil', (req, res) => {
    res.render('perfil'); // Renderiza la vista correspondiente a la página "Perfil"
});

// Ruta principal, renderiza la vista index.ejs y pasa el navbar
app.get('/', (req, res) => {
    res.render('index', { navbar: 'navbar' });
});
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Conexión a la base de datos MongoDB
mongoose.connect('mongodb://localhost:27017/login_demo', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

// Definir el esquema de usuario
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true },
    password: String
});

const User = mongoose.model('User', UserSchema);

// Configurar Passport
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    User.findOne({ email: email })
        .then(user => {
            if (!user) {
                return done(null, false, { message: 'Usuario no encontrado' });
            }
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) { return done(err); }
                if (isMatch) {
                    return done(null, user);
                } else {
                    return done(null, false, { message: 'Contraseña incorrecta' });
                }
            });
        })
        .catch(err => done(err)); // Manejo de error
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then(user => {
            done(null, user);
        })
        .catch(err => done(err)); // Manejo de error
});

// Rutas
app.get('/', (req, res) => {
    res.render('index', { message: req.flash('error') });
});


app.get('/login', (req, res) => {
    res.render('login', { message: req.flash('error') });
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/login',
    failureFlash: true
}));

app.get('/register', (req, res) => {
    res.render('register', { message: req.flash('error') });
});

app.post('/register', (req, res) => {
    const { email, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) throw err;
        const newUser = new User({
            email: email,
            password: hashedPassword
        });
        newUser.save()
            .then(() => {
                res.redirect('/login');
            })
            .catch(err => {
                req.flash('error', 'Error al registrar el usuario');
                res.redirect('/register');
            });
    });
});

app.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', { user: req.user });
});

app.get('/logout', (req, res) => {
    req.logout(err => {
        if (err) {
            console.error('Error during logout:', err);
            return next(err);
        }
        res.redirect('/');
    });
});


// Middleware para verificar la autenticación del usuario
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
