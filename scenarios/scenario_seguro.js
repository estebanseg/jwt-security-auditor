/**
 * scenario_seguro.js
 * --------------------
 * Escenario SEGURO: whitelist explícita de algoritmos, secreto robusto
 * generado aleatoriamente, y validación completa de exp/iss/aud.
 *
 * Uso:
 *   npm install express jsonwebtoken
 *   node scenario_seguro.js
 */
const crypto = require("crypto");
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = 3001;
// Secreto robusto generado en el arranque (en producción vendría de un
// gestor de secretos, nunca hardcodeado ni generado en cada arranque).
const SECRET = crypto.randomBytes(32).toString("hex");
const ISSUER = "jwt-auditor-lab";
const AUDIENCE = "jwt-auditor-clients";

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
    expiresIn: "15m",
    issuer: ISSUER,
    audience: AUDIENCE,
  });
  res.json({ token });
});

function verifyTokenSEGURO(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Token ausente" });

  try {
    // Algoritmo forzado explícitamente (whitelist): jsonwebtoken rechaza
    // automáticamente alg=none o cualquier algoritmo no listado aquí.
    req.user = jwt.verify(token, SECRET, {
      algorithms: ["HS256"],
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido: " + e.message });
  }
}

app.get("/admin", verifyTokenSEGURO, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acceso denegado: se requiere rol admin" });
  }
  res.json({ mensaje: "Acceso admin concedido", usuario: req.user.sub });
});

app.listen(PORT, () => {
  console.log(`[SEGURO] Escuchando en http://localhost:${PORT}`);
});
