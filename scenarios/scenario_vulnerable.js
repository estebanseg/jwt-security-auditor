/**
 * scenario_vulnerable.js
 * ------------------------
 * Escenario VULNERABLE: acepta alg=none y firma con un secreto débil
 * ("secret"), reutilizado deliberadamente de la lista de diccionario
 * por defecto de jwt_auditor para que la herramienta lo detecte.
 *
 * Uso:
 *   npm install express jsonwebtoken
 *   node scenario_vulnerable.js
 */
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = 3000;
const SECRET = "secret"; // Secreto débil A PROPÓSITO (está en cualquier diccionario)

const USERS = {
  alice: { password: "password123", role: "user" },
};

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }
  const token = jwt.sign({ sub: username, role: user.role }, SECRET, {
    algorithm: "HS256",
    expiresIn: "1h",
  });
  res.json({ token });
});

function verifyTokenVULNERABLE(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Token ausente" });

  const parts = token.split(".");
  if (parts.length < 2) return res.status(400).json({ error: "Token malformado" });

  let header, payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch (e) {
    return res.status(400).json({ error: "Token malformado" });
  }

  if (header.alg === "none") {
    req.user = payload;
    return next();
  }

  try {
    req.user = jwt.verify(token, SECRET, { algorithms: ["HS256"] });
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido: " + e.message });
  }
}

app.get("/admin", verifyTokenVULNERABLE, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acceso denegado: se requiere rol admin" });
  }
  res.json({ mensaje: "Acceso admin concedido", usuario: req.user.sub });
});

app.listen(PORT, () => {
  console.log(`[VULNERABLE] Escuchando en http://localhost:${PORT}`);
});
