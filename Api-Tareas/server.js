const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'clave_secreta_tecmilenio';
const TAREAS_FILE = './tareas.json';
const USUARIOS_FILE = './usuarios.json';

app.use(bodyParser.json());
async function leerArchivo(path) {
    const data = await fs.readFile(path, 'utf-8');
    return JSON.parse(data);
}

async function escribirArchivo(path, contenido) {
    await fs.writeFile(path, JSON.stringify(contenido, null, 2));
}
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(403).send({ mensaje: "Token no proporcionado" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).send({ mensaje: "Token inválido" });
        req.userId = decoded.id;
        next();
    });
};
app.post('/register', async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const usuarios = await leerArchivo(USUARIOS_FILE);
        const hashedReqPassword = await bcrypt.hash(password, 10);
        
        const nuevoUsuario = { id: Date.now(), username, password: hashedReqPassword };
        usuarios.push(nuevoUsuario);
        await escribirArchivo(USUARIOS_FILE, usuarios);
        
        res.status(201).send({ mensaje: "Usuario registrado con éxito" });
    } catch (error) { next(error); }
});

app.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const usuarios = await leerArchivo(USUARIOS_FILE);
        const usuario = usuarios.find(u => u.username === username);

        if (usuario && await bcrypt.compare(password, usuario.password)) {
            const token = jwt.sign({ id: usuario.id }, SECRET_KEY, { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).send({ mensaje: "Credenciales inválidas" });
        }
    } catch (error) { next(error); }
});
app.get('/tareas', verificarToken, async (req, res, next) => {
    try {
        const tareas = await leerArchivo(TAREAS_FILE);
        res.json(tareas);
    } catch (error) { next(error); }
});

app.post('/tareas', verificarToken, async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body;
        const tareas = await leerArchivo(TAREAS_FILE);
        const nuevaTarea = { id: Date.now(), titulo, descripcion };
        tareas.push(nuevaTarea);
        await escribirArchivo(TAREAS_FILE, tareas);
        res.status(201).json(nuevaTarea);
    } catch (error) { next(error); }
});

app.put('/tareas/:id', verificarToken, async (req, res, next) => {
    try {
        const tareas = await leerArchivo(TAREAS_FILE);
        const index = tareas.findIndex(t => t.id == req.params.id);
        if (index === -1) return res.status(404).send({ mensaje: "Tarea no encontrada" });

        tareas[index] = { ...tareas[index], ...req.body };
        await escribirArchivo(TAREAS_FILE, tareas);
        res.json(tareas[index]);
    } catch (error) { next(error); }
});
app.delete('/tareas/:id', verificarToken, async (req, res, next) => {
    try {
        let tareas = await leerArchivo(TAREAS_FILE);
        tareas = tareas.filter(t => t.id != req.params.id);
        await escribirArchivo(TAREAS_FILE, tareas);
        res.json({ mensaje: "Tarea eliminada" });
    } catch (error) { next(error); }
});
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send({ error: 'Algo salió mal en el servidor' });
});

app.listen(PORT, () => {
    console.log(`Servidor escuchando en puerto ${PORT}`);
});