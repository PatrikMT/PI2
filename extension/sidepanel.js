const input = document.getElementById("input");
const messages = document.getElementById("messages");
let thinkingDiv = null;

function addMessage(text, sender) {
  const row = document.createElement('div');
  row.className = 'message-row ' + sender;

  const msgDiv = document.createElement('div');
  msgDiv.className = 'message ' + sender;
  msgDiv.innerHTML = text;

  if (sender === 'user') {
    row.appendChild(msgDiv);
  } else {
    // Só a IA tem avatar
    const avatar = document.createElement('div');
    avatar.className = 'avatar ia';
    avatar.textContent = '🤖';
    row.appendChild(avatar);
    row.appendChild(msgDiv);
  }

  document.getElementById('messages').appendChild(row);
  document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

function showThinking() {
  thinkingDiv = document.createElement('div');
  thinkingDiv.className = 'message-row ia';
  const avatar = document.createElement('div');
  avatar.className = 'avatar ia';
  avatar.textContent = '🤖';
  const dots = document.createElement('div');
  dots.className = 'message ia thinking-dots';
  dots.innerHTML = '<span></span><span></span><span></span>';
  thinkingDiv.appendChild(avatar);
  thinkingDiv.appendChild(dots);
  messages.appendChild(thinkingDiv);
  messages.scrollTop = messages.scrollHeight;
}

function hideThinking() {
  if (thinkingDiv) {
    thinkingDiv.remove();
    thinkingDiv = null;
  }
}

async function sendMessage() {
  const text = input.value.trim();
  if (!text) return;

  addMessage(text, "user");
  input.value = "";
  showThinking();

  try {
    const res = await fetch("http://localhost:5000/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text })
    });

    const data = await res.json();
    hideThinking();
    const iaText = data?.reply || "Erro: resposta inválida da IA";
    addMessage("IA: " + iaText, "bot");
  } catch (err) {
    hideThinking();
    addMessage("Erro: " + err.message, "error");
  }
}

function sendQuick(text) {
  input.value = text;
  setTimeout(sendMessage, 0); // Garante que o valor do input seja atualizado antes do envio
}

// Apenas envio por Enter
input.addEventListener("keypress", (e) => {
  if (e.key === "Enter") sendMessage();
});
