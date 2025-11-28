import os
import io
import base64
from typing import List, Dict, Any, Optional

import streamlit as st
from openai import OpenAI

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from audiorecorder import audiorecorder


# ---------------------------------------------------------------------
# CONFIG GMAIL
# ---------------------------------------------------------------------

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"


def get_gmail_service():
    """
    Crée un client Gmail authentifié (OAuth local).
    - Si token.json existe → on l'utilise
    - Sinon → lancement du flux OAuth dans le navigateur

    Basé sur le quickstart officiel Gmail API (Python).
    """
    creds: Optional[Credentials] = None

    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Refresh silencieux
            creds.refresh(Request())
        else:
            # 1ère autorisation : ouvre le navigateur
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES
            )
            creds = flow.run_local_server(port=0)

        # Sauvegarde pour les prochaines fois
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds)
    return service


def list_messages(service, query: str = "", max_results: int = 20) -> List[Dict[str, Any]]:
    """
    Liste des messages (id + infos) selon une requête Gmail.

    Exemples de query :
    - "is:unread"
    - "from:client"
    - "subject:TVA"
    - "has:attachment"
    """
    results = (
        service.users()
        .messages()
        .list(userId="me", q=query, maxResults=max_results)
        .execute()
    )
    messages = results.get("messages", [])
    output = []

    for m in messages:
        msg = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=m["id"],
                format="metadata",
                metadataHeaders=["Subject", "From", "Date"],
            )
            .execute()
        )
        headers = msg.get("payload", {}).get("headers", [])
        header_map = {h["name"]: h["value"] for h in headers}

        output.append(
            {
                "id": m["id"],
                "subject": header_map.get("Subject", ""),
                "from": header_map.get("From", ""),
                "date": header_map.get("Date", ""),
                "snippet": msg.get("snippet", ""),
            }
        )

    return output


def get_email_detail(service, message_id: str) -> Dict[str, Any]:
    """
    Détail complet d'un email :
    - Sujet, expéditeur, date
    - Snippet
    - Corps texte (text/plain si dispo)
    """
    msg = (
        service.users()
        .messages()
        .get(userId="me", id=message_id, format="full")
        .execute()
    )

    headers = msg.get("payload", {}).get("headers", [])
    header_map = {h["name"]: h["value"] for h in headers}

    subject = header_map.get("Subject", "")
    sender = header_map.get("From", "")
    date = header_map.get("Date", "")
    snippet = msg.get("snippet", "")

    # Extraction du corps texte
    body = ""
    payload = msg.get("payload", {})

    def extract_body(part) -> Optional[str]:
        if part.get("mimeType") == "text/plain" and "data" in part.get("body", {}):
            data = part["body"]["data"]
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
        return None

    if "parts" in payload:
        for part in payload["parts"]:
            text = extract_body(part)
            if text:
                body = text
                break
    else:
        if "data" in payload.get("body", {}):
            data = payload["body"]["data"]
            body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

    return {
        "id": message_id,
        "subject": subject,
        "from": sender,
        "date": date,
        "snippet": snippet,
        "body": body,
    }


# ---------------------------------------------------------------------
# CONFIG OPENAI
# ---------------------------------------------------------------------


def get_openai_client() -> OpenAI:
    """
    Initialise le client OpenAI à partir des secrets Streamlit.
    (OPENAI_API_KEY doit être défini dans .streamlit/secrets.toml)
    """
    api_key = st.secrets.get("OPENAI_API_KEY")
    if not api_key:
        st.error(
            "Clé OpenAI manquante.\n\n"
            "Ajoute-la dans .streamlit/secrets.toml sous la forme :\n"
            'OPENAI_API_KEY = "ta_cle_ici"'
        )
        st.stop()
    return OpenAI(api_key=api_key)


def summarize_email(email_body: str, language: str = "fr") -> str:
    """
    Résume un mail avec l'IA.
    """
    if not email_body or not email_body.strip():
        return "(Corps du mail vide ou non disponible)"

    client = get_openai_client()

    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "Tu es un assistant qui résume des emails pour un expert-comptable. "
                    "Tu es factuel, synthétique et tu mets en avant les actions à réaliser."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Résume ce mail en {language} en 5 à 10 lignes max, "
                    f"avec une petite liste à puces pour les actions à faire :\n\n"
                    f"{email_body}"
                ),
            },
        ],
    )
    return completion.choices[0].message.content


def draft_reply(
    email_body: str,
    email_subject: str,
    tone: str = "professionnel et bienveillant",
    language: str = "fr",
) -> str:
    """
    Génère un brouillon de réponse au mail.
    """
    client = get_openai_client()

    prompt = (
        f"Tu es expert-comptable et tu rédiges une réponse email.\n\n"
        f"Sujet du mail reçu : {email_subject}\n\n"
        f"Contenu du mail reçu :\n{email_body}\n\n"
        f"Rédige une réponse en {language}, avec un ton {tone}, clair et structuré, "
        f"en restant réaliste (ne promets pas des choses impossibles). "
        f"Ne commence pas directement par 'Bonjour' dans ton texte, "
        f"je rajouterai la formule de politesse moi-même."
    )

    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "Tu aides un expert-comptable à répondre à ses clients par email. "
                    "Reste professionnel, précis, rassurant."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    )
    return completion.choices[0].message.content


def transcribe_audio(audio_bytes: bytes, language: str = "fr") -> str:
    """
    Transcrit un enregistrement vocal (wav) en texte avec Whisper / transcription OpenAI.

    On utilise BytesIO + .name pour être compatible avec l'API.
    """
    client = get_openai_client()

    audio_file = io.BytesIO(audio_bytes)
    audio_file.name = "message.wav"  # important pour l'API (extension reconnue)

    # Whisper-1 (modèle classique de transcription)
    transcript = client.audio.transcriptions.create(
        model="whisper-1",
        file=audio_file,
        response_format="text",  # la réponse est une simple string
    )

    # Si response_format="text", transcript est déjà une string.
    if isinstance(transcript, str):
        return transcript

    # fallback si c'est un objet
    return getattr(transcript, "text", str(transcript))


def interpret_voice_instruction(transcribed_text: str) -> str:
    """
    Envoie le texte transcrit à l'IA pour le transformer en plan d'action
    ou en réponse structurée.
    """
    client = get_openai_client()

    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "Tu aides un expert-comptable à gérer sa boîte mail Gmail. "
                    "On te fournit une instruction dictée par la voix, déjà transcrite. "
                    "Réponds de manière structurée en expliquant ce que tu proposes de faire, "
                    "comme un plan d'action ou une suggestion détaillée, sans exécuter "
                    "d'actions réelles."
                ),
            },
            {
                "role": "user",
                "content": f"Instruction dictée : {transcribed_text}",
            },
        ],
    )

    return completion.choices[0].message.content


# ---------------------------------------------------------------------
# UI STREAMLIT
# ---------------------------------------------------------------------

st.set_page_config(page_title="Assistant Gmail IA", page_icon="📧", layout="wide")

st.title("📧 Assistant Gmail IA (local)")

st.markdown(
    """
Cet outil tourne **en local** sur ta machine.

Fonctionnalités :
- Connexion à ton Gmail via OAuth (lecture seule)
- Filtrage des mails avec la syntaxe de recherche Gmail
- Affichage détaillé du mail
- Résumé automatique par IA
- Proposition de brouillon de réponse par IA
- 🎙 Enregistrement d'un message vocal et interprétation par l'IA

⚠️ Données :
- Emails récupérés uniquement depuis Google (Gmail API)
- Seul le contenu que tu demandes explicitement à traiter est envoyé à OpenAI
"""
)

# ---------------- Sidebar : options ----------------

st.sidebar.header("🔧 Options Gmail")

default_query = "is:unread"
query = st.sidebar.text_input(
    "Requête Gmail (syntaxe Gmail search)",
    value=default_query,
    help="Exemples : is:unread, from:client, subject:TVA, has:attachment",
)
max_results = st.sidebar.slider("Nombre de mails à charger", 1, 50, 10)

refresh = st.sidebar.button("🔄 Charger / Rafraîchir les mails")

if "email_list" not in st.session_state:
    st.session_state.email_list = []


# ---------------- Chargement des mails ----------------

if refresh:
    try:
        gmail_service = get_gmail_service()
        with st.spinner("Récupération des mails depuis Gmail..."):
            st.session_state.email_list = list_messages(
                gmail_service, query=query, max_results=max_results
            )
        st.success(f"{len(st.session_state.email_list)} mails chargés.")
    except Exception as e:
        st.error(f"Erreur lors de l'accès à Gmail : {e}")


# ---------------- Layout principal ----------------

col_list, col_detail = st.columns([1, 2])

with col_list:
    st.subheader("📬 Liste des mails")

    if not st.session_state.email_list:
        st.info("Clique sur **'Charger / Rafraîchir les mails'** dans la barre de gauche.")
        selected_index = None
    else:
        subjects = [
            f"{i+1}. {m['subject'][:80]} — {m['from']} ({m['date']})"
            for i, m in enumerate(st.session_state.email_list)
        ]
        selected_index = st.radio(
            "Sélectionne un mail :",
            options=list(range(len(subjects))),
            format_func=lambda i: subjects[i],
        )

with col_detail:
    st.subheader("📄 Détail du mail")

    email_detail: Optional[Dict[str, Any]] = None

    if selected_index is not None:
        selected_msg = st.session_state.email_list[selected_index]
        try:
            gmail_service = get_gmail_service()
            email_detail = get_email_detail(gmail_service, selected_msg["id"])
        except Exception as e:
            st.error(f"Erreur lors de la récupération du mail : {e}")
            email_detail = None

    if email_detail:
        st.markdown(f"**Sujet :** {email_detail['subject']}")
        st.markdown(f"**De :** {email_detail['from']}")
        st.markdown(f"**Date :** {email_detail['date']}")
        st.markdown("---")

        with st.expander("Voir l'extrait Gmail (snippet)"):
            st.code(email_detail["snippet"])

        st.markdown("### Corps du mail")
        st.text_area(
            "Texte du mail",
            email_detail["body"] or "(Pas de corps texte disponible)",
            height=250,
        )

        st.markdown("---")
        st.markdown("### 🤖 Actions IA sur ce mail")

        col_a, col_b = st.columns(2)

        with col_a:
            if st.button("📝 Résumer ce mail"):
                with st.spinner("Génération du résumé..."):
                    summary = summarize_email(email_detail["body"])
                st.markdown("#### Résumé proposé")
                st.write(summary)

        with col_b:
            if st.button("✉️ Proposer une réponse"):
                with st.spinner("Rédaction de la réponse..."):
                    reply = draft_reply(
                        email_body=email_detail["body"],
                        email_subject=email_detail["subject"],
                    )
                st.markdown("#### Brouillon de réponse")
                st.write(reply)
                st.info(
                    "Tu peux copier-coller cette réponse dans Gmail, "
                    "l'adapter, puis l'envoyer."
                )

# ---------------------------------------------------------------------
# SECTION MESSAGE VOCAL
# ---------------------------------------------------------------------

st.markdown("---")
st.header("🎙 Parler à l'assistant (message vocal)")

st.markdown(
    """
Enregistre un message vocal pour donner des instructions à l'assistant.

Exemples :
- *"Résume-moi les trois derniers mails non lus."*
- *"Propose une réponse au dernier mail de Mme Dupont concernant la TVA."*
- *"Liste les urgences dans ma boîte de réception."*

💡 L'enregistrement se fait dans ton navigateur (micro).
"""
)

audio = audiorecorder("🔴 Enregistrer", "⏹️ Stop")

if len(audio) > 0:
    # Lecture de l'audio dans le frontend
    st.audio(audio.tobytes(), format="audio/wav")
    st.success("Enregistrement terminé. Tu peux maintenant lancer la transcription.")

    if st.button("🧠 Transcrire et envoyer à l'assistant"):
        with st.spinner("Transcription du message vocal..."):
            transcript_text = transcribe_audio(audio.tobytes())

        st.markdown("#### Texte transcrit")
        st.write(transcript_text)

        with st.spinner("Interprétation par l'assistant..."):
            interpretation = interpret_voice_instruction(transcript_text)

        st.markdown("#### Réponse de l'assistant")
        st.write(interpretation)
