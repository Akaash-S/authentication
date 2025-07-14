// eslint-disable-next-line no-undef
import dotenv from "dotenv";
import express, { json } from "express";
import cors from "cors";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const { sign, verify } = jwt;

const app = express();
// eslint-disable-next-line no-undef
const PORT = process.env.PORT || 3000;
// eslint-disable-next-line no-undef
const JWT_SECRET = process.env.JWT_SECRET || "changeme_securely";

// TEMP USER STORAGE (use DB in prod)
const users = [];

app.use(cors());
app.use(json());

// 🧠 Parse name from email
function getName(email) {
  return email.split("@")[0]
    .replace(/[^a-zA-Z ]/g, " ")
    .split(/[\s._-]+/)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// 🔐 Create JWT token (dynamic & per-user)
function createToken(email) {
  return sign({ email }, JWT_SECRET, { expiresIn: "2h" });
}

// 🧱 Middleware for protected route
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(403).json({ error: "Missing token" });

  const token = auth.split(" ")[1];
  try {
    const decoded = verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ➕ POST /register
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const exists = users.find(u => u.email === email);
  if (exists) return res.status(409).json({ error: "User already exists" });

  const hashed = await hash(password, 12);
  users.push({ email, password: hashed });
  res.status(201).json({ message: "Registered successfully" });
});

// 🔓 POST /login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const match = await compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Invalid credentials" });

  const token = createToken(email);
  const name = getName(email);

  res.json({ token, name });
});

// 🔐 GET /me → protected route
app.get("/me", authMiddleware, (req, res) => {
  res.json({ message: `Hello ${req.user.email}! You're authenticated.` });
});

// 🏁 Root endpoint
app.get("/", (req, res) => {
  res.send("🔥 Auth API running — use /register, /login, /me");
});

// 🚀 Launch server
app.listen(PORT, () => console.log(`✅ Auth API ready on http://localhost:${PORT}`));
