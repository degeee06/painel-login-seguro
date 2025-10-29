const axios = require('axios');
const readline = require('readline');

const API_URL = "https://painel-login-seguro-61ap.onrender.com"; // 🚀 URL do Render
const ADMIN_KEY = process.env.ADMIN_KEY || "ninguemnuncavaidescobrir";

const headers = {
  "Content-Type": "application/json",
  "x-admin-key": ADMIN_KEY,
};

// ==========================
// Funções
// ==========================
async function addUser(email, password, durationMinutes) {
  try {
    const durationSeconds = durationMinutes * 60;
    const res = await axios.post(`${API_URL}/admin/addUser`, { email, password, durationSeconds }, { headers });
    console.log("✅ Usuário criado:", {
      ...res.data,
      durationMinutes
    });
  } catch (err) {
    console.error("❌ Erro:", err.response?.status, err.response?.data || err.message);
  }
}

async function listUsers() {
  try {
    const res = await axios.get(`${API_URL}/admin/listUsers`, { headers });
    // Converte segundos -> minutos só na exibição
    const users = res.data.map(u => ({
      email: u.email,
      durationMinutes: Math.floor(u.duration_seconds / 60),
      start_time: u.start_time
    }));
    console.table(users);
  } catch (err) {
    console.error("❌ Erro:", err.response?.status, err.response?.data || err.message);
  }
}

async function removeUser(email) {
  try {
    const res = await axios.delete(`${API_URL}/admin/removeUser`, { headers, data: { email } });
    console.log("✅ Usuário removido:", res.data);
  } catch (err) {
    console.error("❌ Erro:", err.response?.status, err.response?.data || err.message);
  }
}

async function updateUserTime(email, extraMinutes) {
  try {
    const extraSeconds = extraMinutes * 60;
    const res = await axios.put(
      `${API_URL}/admin/updateUserTime`,
      { email, extraSeconds },
      { headers }
    );
    console.log("✅ Tempo atualizado:", res.data);
  } catch (err) {
    console.error("❌ Erro:", err.response?.status, err.response?.data || err.message);
  }
}
// ==========================
// CLI
// ==========================
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function menu() {
  console.log("\n=== Painel Admin ===");
  console.log("1 - Adicionar usuário");
  console.log("2 - Listar usuários");
  console.log("3 - Remover usuário");
  console.log("4 - Alterar tempo de usuário");
  console.log("0 - Sair");

  rl.question("Escolha uma opção: ", async (op) => {
    switch (op) {
      case "1":
        rl.question("Email: ", (email) => {
          rl.question("Senha: ", (senha) => {
            rl.question("Duração em MINUTOS: ", async (dur) => {
              await addUser(email, senha, parseInt(dur));
              menu();
            });
          });
        });
        break;

      case "2":
        await listUsers();
        menu();
        break;

      case "3":
        rl.question("Email do usuário a remover: ", async (email) => {
          await removeUser(email);
          menu();
        });
        break;

      case "4":
        rl.question("Email do usuário: ", (email) => {
          rl.question("Nova duração em MINUTOS: ", async (dur) => {
            await updateUserTime(email, parseInt(dur));
            menu();
          });
        });
        break;

      case "0":
        rl.close();
        process.exit(0);

      default:
        console.log("Opção inválida!");
        menu();
    }
  });
}

menu();
