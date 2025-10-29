require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// 🔑 Configurações
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const ADMIN_KEY = process.env.ADMIN_KEY || "ninguemnuncavaidescobrir";

// ==========================
// Middlewares
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
  
  if (!email || !password || !durationSeconds) {
    return res.status(400).json({ error: 'Campos obrigatórios faltando' });
  }

  try {
    // Verifica se usuário existe
    const { data: existing } = await supabase
      .from('users')
      .select('email')
      .eq('email', email)
      .single();

    if (existing) return res.status(400).json({ error: 'Usuário já existe' });

    // Cria usuário
    const hashedPassword = await bcrypt.hash(password, 10);
    const { error } = await supabase
      .from('users')
      .insert([{ 
        email, 
        password_hash: hashedPassword, 
        duration_seconds: durationSeconds 
      }]);

    if (error) throw error;

    res.json({ 
      message: 'Usuário criado com sucesso', 
      email, 
      durationSeconds 
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.get('/admin/listUsers', checkAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('email, duration_seconds, start_time');

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

app.delete('/admin/removeUser', checkAdmin, async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email é obrigatório' });
  }

  try {
    const { error } = await supabase
      .from('users')
      .delete()
      .eq('email', email);

    if (error) throw error;
    res.json({ message: 'Usuário removido', email });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao remover usuário' });
  }
});

app.put('/admin/updateUserTime', checkAdmin, async (req, res) => {
  const { email, extraSeconds } = req.body;
  
  if (!email || !extraSeconds) {
    return res.status(400).json({ error: 'Email e extraSeconds são obrigatórios' });
  }

  try {
    // Busca usuário atual
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('duration_seconds')
      .eq('email', email)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Atualiza tempo
    const newDuration = user.duration_seconds + extraSeconds;
    const { error: updateError } = await supabase
      .from('users')
      .update({ duration_seconds: newDuration })
      .eq('email', email);

    if (updateError) throw updateError;

    res.json({
      message: 'Tempo atualizado com sucesso',
      email,
      newDuration
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar tempo' });
  }
});

// ==========================
// Health Check
// ==========================
app.get('/health', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('count')
      .limit(1);

    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      database: error ? 'error' : 'connected'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'ERROR', 
      error: error.message 
    });
  }
});

// ==========================
// Iniciar Servidor
// ==========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Servidor rodando na porta ${PORT}`);
});
