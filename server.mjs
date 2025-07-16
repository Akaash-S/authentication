// eslint-disable-next-line no-undef
import dotenv from "dotenv";
import express, { json } from "express";
import cors from "cors";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

dotenv.config();

const { sign, verify } = jwt;

const app = express();
// eslint-disable-next-line no-undef
const PORT = process.env.PORT || 3000;
// eslint-disable-next-line no-undef
const JWT_SECRET = process.env.JWT_SECRET || "changeme_securely";

// TEMP USER STORAGE (use DB in prod)
const users = [];

// In-memory store for verification tokens: { token: { email, expiresAt } }
const verificationTokens = {};

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

// Nodemailer transporter (Ethereal for dev, SMTP for prod)
async function createTransporter() {
  if (process.env.NODE_ENV === "production") {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      tls: {
        rejectUnauthorized: false // Allow self-signed certs (not recommended for real production)
      }
    });
  } else {
    // Ethereal for dev
    const testAccount = await nodemailer.createTestAccount();
    return nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      secure: false,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
      tls: {
        rejectUnauthorized: false // Allow self-signed certs in dev
      }
    });
  }
}

// Generate a random token (could use JWT, but random string is fine for demo)
function generateToken(length = 48) {
  return [...Array(length)].map(() => Math.random().toString(36)[2]).join("");
}

// 🔢 Generate a 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// In-memory store for OTPs: { [email]: { otp, expiresAt } }
const otpStore = {};

// ➕ POST /register (with email verification)
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  let user = users.find(u => u.email === email);
  if (user) return res.status(409).json({ error: "User already exists" });

  const hashed = await hash(password, 12);
  user = { email, password: hashed, verified: false };
  users.push(user);

  // Generate verification token
  const token = generateToken();
  const expiresAt = Date.now() + 1000 * 60 * 60; // 1 hour
  verificationTokens[token] = { email, expiresAt };

  // Send verification email
  const transporter = await createTransporter();
  const verifyUrl = `http://localhost:${PORT}/verify?token=${token}`;
  const mailOptions = {
    from: 'No Reply <no-reply@example.com>',
    to: email,
    subject: 'Verify your email',
    text: `Click the link to verify your email: ${verifyUrl}`,
    html: `<p>Click the link to verify your email: <a href=\"${verifyUrl}\">${verifyUrl}</a></p>`
  };
  try {
    const info = await transporter.sendMail(mailOptions);
    if (process.env.NODE_ENV !== "production") {
      // Provide Ethereal preview URL for dev
      res.status(201).json({
        message: "Registered successfully. Verification email sent.",
        preview: nodemailer.getTestMessageUrl(info), // <-- This is the link to view the email in dev
        verifyUrl // Also return the direct verification URL for convenience
      });
    } else {
      res.status(201).json({ message: "Registered successfully. Verification email sent." });
    }
  } catch (err) {
    console.error("Email send error:", err);
    res.status(500).json({ error: "Failed to send verification email" });
  }
});

// 📨 GET /verify?token=...
app.get("/verify", (req, res) => {
  const { token } = req.query;
  if (!token || !verificationTokens[token]) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }
  const { email, expiresAt } = verificationTokens[token];
  if (Date.now() > expiresAt) {
    delete verificationTokens[token];
    return res.status(400).json({ error: "Token expired" });
  }
  const user = users.find(u => u.email === email);
  if (!user) {
    delete verificationTokens[token];
    return res.status(400).json({ error: "User not found" });
  }
  if (user.verified) {
    delete verificationTokens[token];
    return res.status(400).json({ error: "User already verified" });
  }
  user.verified = true;
  delete verificationTokens[token];
  res.json({ message: "Email verified successfully!" });
});

// 📤 POST /send-otp (send OTP to user's email)
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  // Generate OTP and expiry (5 min)
  const otp = generateOTP();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  otpStore[email] = { otp, expiresAt };

  // Send OTP via email
  const transporter = await createTransporter();
  const mailOptions = {
    from: 'No Reply <no-reply@example.com>',
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is: ${otp}`,
    html: `<p>Your OTP code is: <b>${otp}</b></p>`
  };
  try {
    const info = await transporter.sendMail(mailOptions);
    if (process.env.NODE_ENV !== "production") {
      res.json({ message: "OTP sent", preview: nodemailer.getTestMessageUrl(info) });
    } else {
      res.json({ message: "OTP sent" });
    }
  } catch (err) {
    console.error("OTP email send error:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// ✅ POST /verify-otp (verify OTP for user)
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

  const record = otpStore[email];
  if (!record) return res.status(400).json({ error: "No OTP requested for this email" });
  if (Date.now() > record.expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ error: "OTP expired" });
  }
  if (record.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });

  delete otpStore[email];
  res.json({ message: "OTP verified successfully" });
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

// ➖ POST /delete (delete user by email, requires password)
app.post("/delete", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }
  const userIndex = users.findIndex(u => u.email === email);
  if (userIndex === -1) {
    return res.status(404).json({ error: "User not found" });
  }
  const user = users[userIndex];
  const match = await compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  users.splice(userIndex, 1);
  res.json({ message: "User deleted successfully" });
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
