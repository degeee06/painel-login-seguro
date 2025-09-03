require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.use(express.json({
  strict: true,
  verify: (req, res, buf) => {
    if (!buf || !buf.length) req.body = {};
  }
}));

// captura JSON inválido
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'JSON inválido ou nulo' });
  }
  next();
});

// 🔑 Credenciais
const supabase = createClient(process.env.SUPABASE_URL, process.env.SERVICE_ROLE_KEY);
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
    .insert([{ email, password_hash: passwordHash, duration_seconds: durationSeconds, start_time: null, current_token: null }]);
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
    return res.status(400).json({ error: 'Campos obrigatórios faltando ou JSON inválido' });

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
  if (!req.body || !req.body.email)
    return res.status(400).json({ error: 'JSON inválido ou email faltando' });

  const { email } = req.body;
  const { error } = await supabase.from('users').delete().eq('email', email);
  if (error) return res.status(500).json({ error });

  res.json({ message: 'Usuário removido', email });
});

app.put('/admin/updateUserTime', checkAdmin, async (req, res) => {
  if (!req.body || !req.body.email || !req.body.extraSeconds)
    return res.status(400).json({ error: 'JSON inválido ou campos obrigatórios faltando' });

  const { email, extraSeconds } = req.body;
  const user = await getUser(email);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

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
// Middleware para token único
// ==========================
async function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Sem autorização' });

  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await getUser(payload.email);
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

    // verifica se o token atual bate com o do banco
    if (user.current_token !== token)
      return res.status(403).json({ error: 'Usuário deslogado em outro dispositivo' });

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// ==========================
// Rotas USER
// ==========================
app.post('/login', async (req, res) => {
  const { email, password, device_id } = req.body;
  if (!email || !password || !device_id)
    return res.status(400).json({ error: 'Campos obrigatórios faltando' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(400).json({ error: 'Usuário não encontrado' });

  const senhaValida = await bcrypt.compare(password, user.password_hash);
  if (!senhaValida) return res.status(401).json({ error: 'Senha inválida' });

  if (!user.start_time) {
    await setStartTime(user.email, Date.now());
    user.start_time = Date.now();
  }

  const elapsed = (Date.now() - user.start_time) / 1000;
  const timeRemaining = Math.max(0, user.duration_seconds - elapsed);
  if (timeRemaining <= 0) return res.status(403).json({ error: 'Licença expirada' });

  // Atualiza device_id do usuário no banco
  await supabase.from('users').update({ device_id }).eq('email', user.email);

  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: `${Math.floor(timeRemaining)}s` });
  await supabase.from('users').update({ current_token: token }).eq('email', user.email);

  res.json({ token, timeRemaining: Math.floor(timeRemaining) });
});

app.post('/sessions/validate', verifyToken, async (req, res) => {
  const { email, device_id } = req.body;
  const user = await getUser(email);
  if (!user) return res.json({ valid: false });

  const valid = user.current_token === req.headers['authorization'].split(' ')[1]
                && user.device_id === device_id;

  res.json({ valid });
});

// ==========================
// Rota REFRESH TOKEN
// ==========================
app.post('/refresh', verifyToken, async (req, res) => {
  const user = req.user;

  const elapsed = (Date.now() - user.start_time) / 1000;
  const timeRemaining = Math.max(0, user.duration_seconds - elapsed);

  if (timeRemaining <= 0) return res.status(403).json({ error: 'Licença expirada' });

  const newToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: `${Math.floor(timeRemaining)}s` });
  await supabase.from('users').update({ current_token: newToken }).eq('email', user.email);

  res.json({ token: newToken, timeRemaining: Math.floor(timeRemaining) });
});

// ==========================
// Check Licença
// ==========================
app.get('/check', verifyToken, async (req, res) => {
  const user = req.user;
  const elapsed = (Date.now() - user.start_time) / 1000;
  const timeRemaining = Math.max(0, user.duration_seconds - elapsed);

  if (timeRemaining <= 0) return res.status(403).json({ error: 'Licença expirada' });

  res.json({ email: user.email, timeRemaining: Math.floor(timeRemaining) });
});

// ==========================
// Start server
// ==========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Servidor rodando na porta ${PORT}`));
