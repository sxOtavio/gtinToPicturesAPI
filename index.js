require("dotenv").config();

const express = require("express");
const app = express();

const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");

const JWT_SECRET = process.env.JWT_SECRET;
const BASE_URL = process.env.BASE_URL;

app.use(express.json());
app.use(cors());

app.use("/images", express.static(path.join(__dirname, "images")));

// ================= BANCO =================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("neon.tech")
    ? { rejectUnauthorized: false }
    : false,
});

console.log("Banco configurado");

// ================= MULTER =================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./images");
  },

  filename: (req, file, cb) => {
    const gtin = req.body.gtin;

    cb(null, `${gtin}.jpg`);
  },
});

const upload = multer({ storage });

// ================= AUTH =================

function authenticateToken(req, res, next) {
  const token = req.query.token;

  if (!token) {
    return res.status(401).json({
      error: "Token obrigatório",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({
      error: "Token inválido",
    });
  }
}

// ================= HEALTH =================

app.get("/health", (req, res) => {
  res.json({
    status: "online",
    timestamp: new Date(),
  });
});

// ================= LOGIN =================

app.post("/login", async (req, res) => {
  const { user, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM login WHERE username = $1", [
      user,
    ]);

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Usuário não encontrado",
      });
    }

    const bankUser = result.rows[0];

    const passwordOk = await bcrypt.compare(password, bankUser.password);

    if (!passwordOk) {
      return res.status(401).json({
        error: "Senha inválida",
      });
    }

    const token = jwt.sign(
      {
        id: bankUser.id,
        username: bankUser.username,
      },
      JWT_SECRET,
      {
        expiresIn: "5h",
      },
    );

    res.json({
      success: true,
      token,
      id: bankUser.id,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro interno",
    });
  }
});

// ================= REGISTRO =================

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const exists = await pool.query(
      "SELECT id FROM login WHERE username = $1",
      [email],
    );

    if (exists.rows.length > 0) {
      return res.status(409).json({
        error: "Usuário já existe",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO login
      (
        username,
        password,
        name,
        active
      )
      VALUES
      (
        $1,
        $2,
        $3,
        false
      )
      RETURNING id
      `,
      [email, hashedPassword, name],
    );

    res.status(201).json({
      success: true,
      userId: result.rows[0].id,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao registrar",
    });
  }
});

// ================= CATÁLOGO =================

app.get("/api/catalog", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT gtin FROM product_images");

    const images = {};

    result.rows.forEach((row) => {
      images[row.gtin] = `${BASE_URL}/images/${row.gtin}.jpg`;
    });

    res.set("Cache-Control", "public, max-age=3600");

    res.json(images);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao buscar catálogo",
    });
  }
});

// ================= UPLOAD =================

app.post(
  "/api/upload",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const { gtin } = req.body;

      if (!gtin) {
        return res.status(400).json({
          error: "GTIN obrigatório",
        });
      }

      await pool.query(
        `
        INSERT INTO product_images
        (gtin, created_at
        )
        VALUES
        (
          $1,
          NOW()
        )
        ON CONFLICT (gtin)
        DO NOTHING
        `,
        [gtin],
      );

      res.json({
        success: true,
        gtin,
        image_url: `${BASE_URL}/images/${gtin}.jpg`,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Erro ao enviar imagem",
      });
    }
  },
);

// ================= SERVIDOR =================

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
