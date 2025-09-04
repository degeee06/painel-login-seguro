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
// Middleware para token
// ==========================
async function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Sem autorização' });

  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { data: session } = await supabase
      .from('user_sessions')
      .select('*')
      .eq('email', payload.email)
      .eq('device_id', payload.device_id)
      .eq('token', token)
      .single();

    if (!session) return res.status(403).json({ error: 'Usuário deslogado em outro dispositivo' });

    req.user = { email: payload.email, device_id: payload.device_id };
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

  const user = await getUser(email);
  if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

  const senhaValida = await bcrypt.compare(password, user.password_hash);
  if (!senhaValida) return res.status(401).json({ error: 'Senha inválida' });

  if (!user.start_time) {
    await setStartTime(user.email, Date.now());
    user.start_time = Date.now();
  }

  const elapsed = (Date.now() - user.start_time) / 1000;
  const timeRemaining = Math.max(0, user.duration_seconds - elapsed);
  if (timeRemaining <= 0) return res.status(403).json({ error: 'Licença expirada' });

  const token = jwt.sign({ email, device_id }, JWT_SECRET, { expiresIn: `${Math.floor(timeRemaining)}s` });

  // Salva sessão por device_id
// Remove sessões antigas do mesmo email em outros devices
await supabase.from('user_sessions')
  .delete()
  .eq('email', email)
  .neq('device_id', device_id);

// Salva a nova sessão do device atual
await supabase.from('user_sessions')
  .upsert([{ email, device_id, token }]);

  res.json({ token, timeRemaining: Math.floor(timeRemaining) });
});

app.post('/sessions/validate', verifyToken, async (req, res) => {
  const { email, device_id } = req.body;
  const { data: session } = await supabase
    .from('user_sessions')
    .select('*')
    .eq('email', email)
    .eq('device_id', device_id)
    .single();

  res.json({ valid: !!session });
});

// ==========================
// Refresh token
// ==========================
app.post('/refresh', verifyToken, async (req, res) => {
  const { email, device_id } = req.user;
  const user = await getUser(email);

  const elapsed = (Date.now() - user.start_time) / 1000;
  const timeRemaining = Math.max(0, user.duration_seconds - elapsed);
  if (timeRemaining <= 0) return res.status(403).json({ error: 'Licença expirada' });

  const newToken = jwt.sign({ email, device_id }, JWT_SECRET, { expiresIn: `${Math.floor(timeRemaining)}s` });
  await supabase.from('user_sessions')
    .upsert([{ email, device_id, token: newToken }]);

  res.json({ token: newToken, timeRemaining: Math.floor(timeRemaining) });
});

// ==========================
// Check Licença
// ==========================
app.get('/check', verifyToken, async (req, res) => {
  const { email, device_id } = req.user;
  const user = await getUser(email);

  const elapsed = (Date.now() - user.start_time) / 1000;
  const timeRemaining = Math.max(0, user.duration_seconds - elapsed);

  if (timeRemaining <= 0) return res.status(403).json({ error: 'Licença expirada' });

  res.json({ email, device_id, timeRemaining: Math.floor(timeRemaining) });
});

// ==========================
// Start server
// ==========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Servidor rodando na porta ${PORT}`));
