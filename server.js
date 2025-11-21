require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./db.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticateToken, authorizeRol } = require('./middleware/auth.js');

const app = express();
const PORT = process.env.PORT || 3300;
const JWT_SECREET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

app.get('/status', (req, res) => {
    res.json({ok: true, service: 'film-api'})
})

app.post('/auth/register', async (req, res, next) => {
  // Baris 24: Mengambil username dan password dari body permintaan (yang telah di-parse oleh express.json())
  const { username, password } = req.body;

  // Baris 25-27: Validasi input dasar: pastikan username dan password ada, dan password minimal 6 karakter
  if (!username || !password || password.length < 6) {
    return res.status(400).json({
      error: 'Username dan password (min 6 char) harus diisi'
    });
  }

  try {
    // Baris 29: Menghasilkan 'salt' acak yang akan digunakan untuk mengacak sandi
    const salt = await bcrypt.genSalt(10);

    // Baris 30: Mengenkripsi (hashing) password menggunakan salt. Ini wajib untuk keamanan!
    const hashedPassword = await bcrypt.hash(password, salt);

    // Baris 31: Perintah SQL untuk memasukkan pengguna baru ke tabel 'users'
    const sql = 'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username';

    // Baris 32: Menjalankan query ke database
    // ($1, $2, $3) adalah placeholder yang mencegah serangan SQL Injection,
    // diisi oleh [username yang diubah ke huruf kecil, sandi terenkripsi, 'user' default role]
    const result = await db.query(sql, [username.toLowerCase(), hashedPassword, 'user']);

    // Baris 33: Mengirim respons sukses (status 201 Created) dengan data pengguna baru yang dibuat
    res.status(201).json(result.rows[0]);

  } catch (err) {
    // Baris 35: Memeriksa apakah error disebabkan oleh pelanggaran batasan unik (misalnya, username sudah ada)
    if (err.code === '23505') { // '23505' adalah kode error PostgreSQL untuk unique_violation
      // Baris 36-37: Mengirim respons konflik (status 409 Conflict)
      return res.status(409).json({
        error: 'Username sudah digunakan'
      });
    }

    // Baris 38: Meneruskan error lainnya ke handler error Express default
    next(err);
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Rute tidak ditemukan' });
});

app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.stack);
  res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server aktif di http://localhost:${PORT}`);
});