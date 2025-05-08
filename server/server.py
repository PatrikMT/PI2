import time
import requests
import os
import logging
import secrets
import json
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ========== Setup Inicial ==========
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(24))
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_config():
    with open("config.json", "r") as file:
        return json.load(file)

# ========== Gemini IA ==========
chat_history = []

def query_gemini(msg):
    global chat_history
    # Prompt de contexto para limitar o escopo
    contexto = (
        "ATENÇÃO: Você é um assistente especializado em TI, cibersegurança, programação e boas práticas para estudantes. "
        "Responda SOMENTE perguntas relacionadas a esses temas. "
        "Se a pergunta não for sobre TI, cibersegurança, programação ou boas práticas para estudantes, responda educadamente que só pode responder sobre esses assuntos e peça para o usuário perguntar algo relacionado.\n\n"
    )
    prompt = contexto + msg
    # Adicione a mensagem atual ao histórico
    chat_history.append({"role": "user", "parts": [{"text": prompt}]})
    # Limite o histórico (ex: últimas 10 interações)
    chat_history = chat_history[-10:]
    payload = { "contents": chat_history }
    logging.info(f"🤖 Consultando Gemini com: '{msg[:50]}...'")
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        logging.error("❌ GEMINI_API_KEY não definida.")
        return "❌ Chave da IA não configurada."
    model = "gemini-1.5-flash-latest"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        gemini_data = response.json()
        if "candidates" in gemini_data and gemini_data["candidates"]:
            part = gemini_data["candidates"][0].get("content", {}).get("parts", [{}])[0]
            text = part.get("text", "")
            logging.info("✅ Resposta Gemini recebida.")
            chat_history.append({"role": "model", "parts": [{"text": text}]})
            return text.strip() if text else "🤔 Resposta vazia da IA."
        else:
            logging.warning(f"⚠️ Resposta Gemini inesperada: {gemini_data}")
            return "🤔 IA não retornou resposta válida."
    except requests.exceptions.RequestException as req_e:
        logging.error(f"❌ Erro comunicação Gemini: {req_e}")
        return "❌ Erro ao falar com a IA."
    except Exception as e:
        logging.error(f"❌ Erro Gemini: {e}")
        return "❌ Erro interno IA."

# ========== Consulta CVEs Recentes ==========
def get_recent_cves(vendor, product, limit=3):
    """
    Consulta CVEs recentes para um software usando a API cve.circl.lu.
    Mostra apenas os 'limit' mais recentes.
    """
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    print(f"[DEBUG] Link de pesquisa CVE: {url}")
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        print("[DEBUG] JSON retornado:", data)
        cves = data.get("data", [])[:limit]
        if not cves:
            return "Nenhuma vulnerabilidade recente encontrada para esse software."
        reply = f"Top {len(cves)} vulnerabilidades recentes para {vendor} {product}:\n"
        for cve in cves:
            cve_id = cve.get('id', 'N/A')
            summary = cve.get('summary', 'Sem descrição.')
            link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            reply += f"- {cve_id}: {summary}\n"
        return reply
    except Exception as e:
        return f"Erro ao consultar CVEs: {e}"

# ========== Consulta AbuseIPDB ==========
def check_ip_abuse(ip):
    
    config = load_config()
    api_key = config.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return "❌ Chave da API AbuseIPDB não configurada."
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        try:
            data = response.json()["data"]
        except Exception:
            return f"Erro: resposta inesperada da API AbuseIPDB:\n{response.text}"
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country = data.get("countryCode", "N/A")
        domain = data.get("domain", "N/A")
        return (
            f"IP: {ip}\n"
            f"Abuse Score: {abuse_score}/100\n"
            f"Total de denúncias: {total_reports}\n"
            f"País: {country}\n"
            f"Domínio: {domain if domain else 'N/A'}"
        )
    except Exception as e:
        return f"Erro ao consultar AbuseIPDB: {e}"

def format_ia_response(text):
    # Negrito para Markdown
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    # Itálico para Markdown
    text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
    # Quebra de linha dupla para <br><br>
    text = text.replace('\n\n', '<br><br>')
    # Quebra de linha simples para <br>
    text = text.replace('\n', '<br>')
    return text

def get_cves_nvd(product, limit=3):
    config = load_config()
    api_key = config.get("NVD_API_KEY")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}&resultsPerPage={limit}"
    headers = {"apiKey": api_key} if api_key else {}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        cves = data.get("vulnerabilities", [])[:limit]
        if not cves:
            return "Nenhuma vulnerabilidade recente encontrada para esse produto."
        reply = f"Top {len(cves)} CVEs recentes para '{product}':<br>"
        for cve in cves:
            cve_id = cve['cve']['id']
            desc = cve['cve']['descriptions'][0]['value']
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            reply += f"- <b><a href='{link}' target='_blank'>{cve_id}</a></b>: {desc}<br>"
        return reply
    except Exception as e:
        return f"Erro ao consultar CVEs na NVD: {e}"

def get_github_status():
    url = "https://www.githubstatus.com/api/v2/status.json"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        status = data['status']['description']
        return f"Status do GitHub: {status}"
    except Exception as e:
        return f"Erro ao consultar status do GitHub: {e}"

# ========== Rota Principal da API (/chat) ==========
@app.route('/chat', methods=['POST'])
def chat():
    start_time = time.time()
    if not request.is_json: return jsonify({"error": "Req JSON."}), 415
    data = request.get_json()
    msg = data.get("message", "").strip() if data else ""
    if not msg: return jsonify({"error": "Msg ausente."}), 400

    # Comandos especiais
    if msg.lower().startswith("/cve "):
        partes = msg[5:].strip().split()
        if len(partes) < 2:
            reply = "Por favor, use o formato: /cve <vendor> <produto>\nExemplo: /cve google chrome"
        else:
            vendor = partes[0]
            product = "_".join(partes[1:])  # Permite nomes compostos, ex: windows_10
            reply = get_cves_nvd(product)
    elif msg.lower().startswith("/ip "):
        ip = msg[4:].strip()
        reply = check_ip_abuse(ip)
    elif msg.lower().startswith("/status github"):
        reply = get_github_status()
    elif msg.lower().startswith("/help"):
        reply = (
            "Comandos disponíveis:<br>"
            "/cve <produto> — Consulta CVEs<br>"
            "/ip <ip> — Consulta IP<br>"
            "/status github — Status do GitHub<br>"
            "/help — Mostra esta ajuda<br>"
        )
    else:
        # Explicação de conceito, boas práticas, etc.
        resposta_ia = query_gemini(msg)
        reply = format_ia_response(resposta_ia)

    end_time = time.time()
    logging.info(f"--- Req /chat fim ({end_time - start_time:.2f}s) ---")
    return jsonify({"reply": reply})

# ========== Execução do Servidor ==========
if __name__ == "__main__":
    logging.info("🚀 Iniciando servidor Flask API para Assistente de TI...")
    limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])
    app.run(host='0.0.0.0', port=5000, debug=True)