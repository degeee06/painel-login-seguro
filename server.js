require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// 🔑 Credenciais
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const ADMIN_KEY = process.env.ADMIN_KEY || "ninguemnuncavaidescobrir";

// ==========================
// Funções auxiliares
// ==========================
async function getUser(email) {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();
  if (error) return null;
  return data;
}

async function addUser(email, passwordHash, durationSeconds) {
  const { error } = await supabase
    .from('users')
    .insert([{ email, password_hash: passwordHash, duration_seconds: durationSeconds, start_time: null }]);
  if (error) throw error;
}

async function setStartTime(email, startTime) {
  const { error } = await supabase
    .from('users')
    .update({ start_time: startTime })
    .eq('email', email);
  if (error) throw error;
}

// ==========================
// Middleware admin
// ==========================
function checkAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Admin key inválida' });
  }
  next();
}

// ==========================
// Rotas ADMIN
// ==========================
app.post('/admin/addUser', checkAdmin, async (req, res) => {
  const { email, password, durationSeconds } = req.body;
  if (!email || !password || !durationSeconds)
    return res.status(400).json({ error: 'Campos obrigatórios' });

  try {
    const existing = await getUser(email);
    if (existing) return res.status(400).json({ error: 'Usuário já existe' });

    const hashed = await bcrypt.hash(password, 10);
    await addUser(email, hashed, durationSeconds);

    res.json({ message: 'Usuário criado com sucesso', email, durationSeconds });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor', details: err.message });
  }
});

app.get('/admin/listUsers', checkAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('email, duration_seconds, start_time');
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.delete('/admin/removeUser', checkAdmin, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email necessário' });

  const { error } = await supabase.from('users').delete().eq('email', email);
  if (error) return res.status(500).json({ error });

  res.json({ message: 'Usuário removido', email });
});

app.put('/admin/updateUserTime', checkAdmin, async (req, res) => {
  const { email, extraSeconds } = req.body; 
  if (!email || !extraSeconds) {
    return res.status(400).json({ error: 'Campos obrigatórios' });
  }

  const user = await getUser(email);
  if (!user) {
    return res.status(404).json({ error: 'Usuário não encontrado' });
  }

  // soma o tempo extra ao total atual
  const newDuration = user.duration_seconds + extraSeconds;

  const { error } = await supabase
    .from('users')
    .update({ duration_seconds: newDuration })
    .eq('email', email);

  if (error) return res.status(500).json({ error });

  res.json({
    message: '⏱ Tempo estendido com sucesso',
    email,
    oldDuration: user.duration_seconds,
    extraSeconds,
    newDuration
  });
});


// ==========================
// Rotas USER
// ==========================
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(400).json({ error: 'Usuário não encontrado' });

  const senhaValida = await bcrypt.compare(password, user.password_hash);
  if (!senhaValida) return res.status(401).json({ error: 'Senha inválida' });

  // se nunca logou, marca o start_time
  if (!user.start_time) {
    await setStartTime(user.email, Date.now());
    user.start_time = Date.now();
  }

  const elapsed = (Date.now() - user.start_time) / 1000; // em segundos
  const timeRemaining = Math.max(0, user.duration_seconds - elapsed);

  if (timeRemaining <= 0)
    return res.status(403).json({ error: 'Licença expirada' });

  const token = jwt.sign(
    { email: user.email },
    JWT_SECRET,
    { expiresIn: `${Math.floor(timeRemaining)}s` }
  );

  res.json({
    token,
    timeRemaining: Math.floor(timeRemaining) // sempre em segundos
  });
});

// ==========================
// Rota REFRESH TOKEN
// ==========================
app.post('/refresh', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Sem autorização' });

  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });

    const user = await getUser(payload.email);
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

    const elapsed = (Date.now() - user.start_time) / 1000;
    const timeRemaining = Math.max(0, user.duration_seconds - elapsed);

    if (timeRemaining <= 0)
      return res.status(403).json({ error: 'Licença expirada' });

    const newToken = jwt.sign(
      { email: user.email },
      JWT_SECRET,
      { expiresIn: `${Math.floor(timeRemaining)}s` }
    );

    res.json({
      token: newToken,
      timeRemaining: Math.floor(timeRemaining) // sempre em segundos
    });
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ==========================
// Check Licença
// ==========================
app.get('/check', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Sem autorização' });

  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await getUser(payload.email);
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

    const elapsed = (Date.now() - user.start_time) / 1000;
    const timeRemaining = Math.max(0, user.duration_seconds - elapsed);

    if (timeRemaining <= 0) return res.status(403).json({ error: 'Licença expirada' });

    res.json({
      email: payload.email,
      timeRemaining: Math.floor(timeRemaining) // sempre em segundos
    });
  } catch (err) {
    res.status(401).json({ error: 'Token inválido ou expirado' });
  }
});

// ==========================
// Start server
// ==========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Servidor rodando na porta ${PORT}`));
