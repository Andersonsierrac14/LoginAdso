const express = require("express");
const dbconnect = require("./config");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ModelUser = require("./model");
const app = express();

const router = express.Router();
const SECRET_KEY = "your_secret_key"; 

app.use(express.json());

// Registro de usuario
router.post('/register', async (req, res) => {
    const { nomuser, password } = req.body;

    if (!nomuser || !password) {
        return res.status(400).send("El nombre de usuario y la contraseña son obligatorios");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new ModelUser({ nomuser, password: hashedPassword });

    try {
        const savedUser = await user.save();
        res.status(201).send(savedUser);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Inicio de sesión
router.post('/login', async (req, res) => {
    const { nomuser, password } = req.body;

    if (!nomuser || !password) {
        return res.status(400).send("El nombre de usuario y la contraseña son obligatorios");
    }

    try {
        const user = await ModelUser.findOne({ nomuser });

        if (!user) {
            return res.status(401).send("Fallo en la autenticación: Usuario no encontrado");
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).send("Fallo en la autenticación: Contraseña incorrecta");
        }

        const token = jwt.sign({ id: user._id, nomuser: user.nomuser }, SECRET_KEY, { expiresIn: "1h" });
        res.send({ message: "Autenticación exitosa", token });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Consultar todos los usuarios
router.get('/', async (req, res) => {
    try {
        const users = await ModelUser.find({});
        res.status(200).send(users);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Consultar usuario por ID
router.get('/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const user = await ModelUser.findById(id);
        if (!user) {
            return res.status(404).send("Usuario no encontrado");
        }
        res.status(200).send(user);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Actualizar usuario por ID
router.put('/:id', async (req, res) => {
    const { id } = req.params;
    const { nomuser, password } = req.body;

    try {
        const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;
        const updateData = { nomuser, ...(hashedPassword && { password: hashedPassword }) };

        const updatedUser = await ModelUser.findByIdAndUpdate(id, updateData, { new: true });
        if (!updatedUser) {
            return res.status(404).send("Usuario no encontrado");
        }
        res.status(200).send(updatedUser);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Eliminar usuario por ID
router.delete('/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const deletedUser = await ModelUser.findByIdAndDelete(id);
        if (!deletedUser) {
            return res.status(404).send("Usuario no encontrado");
        }
        res.status(200).send("Usuario eliminado exitosamente");
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.use(router);
app.listen(3005, () => {
    console.log("El servidor está en el puerto 3005");
});

dbconnect();