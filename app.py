import io
import json
import base64
from typing import List, Dict, Any, Optional

import streamlit as st
from openai import OpenAI

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow


# ---------------------------------------------------------------------
# Utilitaires Streamlit pour les query params (compat anciens / nouveaux)
# ---------------------------------------------------------------------


def get_query_param(name: str) -> Optional[str]:
    """
    Récupère un paramètre d'URL (ex: code, state), compatible
    avec st.query_params (nouveau) et st.experimental_get_query_params (ancien).
    """
    # Nouveaux Streamlit
    try:
        params = st.query_params
        value = params.get(name)
    except Exception:
        # Anciens Streamlit
        params = st.experimental_get_query_params()
        value = params.get(name)

    if isinstance(value, list):
        return value[0] if value else None
    return value


def clear_query_params():
    """
    Tente de nettoyer les query params dans l'URL (optionnel).
    """
    try:
        st.query_params.clear()
    except Exception:
        # Compat anciennes versions
        try:
            st.experimental_set_query_params()
        except Exception:
            pass


# ---------------------------------------------------------------------
# CONFIG GMAIL (100% WEB, via secrets)
# ---------------------------------------------------------------------

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def get_google_oauth_config() -> Dict[str, Any]:
    """
    Lit la config OAuth depuis les secrets Streamlit :
    [google_oauth]
    client_id = "..."
    client_secret = "..."
    redirect_uri = "https://ton-app.streamlit.app/"
    """
    cfg = st.secrets.get("google_oauth", None)
    if not cfg:
        st.error(
            "Section [google_oauth] manquante dans les secrets Streamlit.\n\n"
            "Va dans 'Manage app' → 'Settings' → 'Secrets' et ajoute :\n\n"
            "[google_oauth]\n"
            'client_id = "xxx.apps.googleusercontent.com"\n'
            'client_secret = "xxxxx"\n'
            'redirect_uri = "https://ton-app.streamlit.app/"\n'
        )
        st.stop()
    return cfg


def build_flow(redirect_uri: str) -> Flow:
    """
    Construit un Flow OAuth Web à partir des infos en secrets.
    On n'utilise PLUS de credentials.json local.
    """
    oauth_cfg = get_google_oauth_config()
    client_id = oauth_cfg["client_id"]
    client_secret = oauth_cfg["client_secret"]

    client_config = {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )
    return flow


def get_credentials_from_session() -> Optional[Credentials]:
    """
    Récupère les credentials depuis la session Streamlit, si déjà authentifié.
    """
    creds_json = st.session_state.get("google_credentials")
    if not creds_json:
        return None

    data = json.loads(creds_json)
    return Credentials.from_authorized_user_info(data, SCOPES)


def store_credentials_in_session(creds: Credentials):
    """
    Stocke les credentials en JSON dans st.session_state.
    (Rien n'est écrit sur disque, tout reste en mémoire côté serveur.)
    """
    info = {
        "token": creds.token,
        "refresh_token": getattr(creds, "refresh_token", None),
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": list(creds.scopes),
    }
    st.session_state["google_credentials"] = json.dumps(info)


def ensure_logged_in_and_get_credentials() -> Optional[Credentials]:
    """
    Gère toute la logique OAuth Web :
    - Si pas connecté → affiche un bouton 'Se connecter avec Google'
    - Si on revient de Google avec ?code=... → échange le code contre un token
    - Stocke les credentials en session
    - Renvoie les credentials utilisables pour l'API Gmail
    """
    creds = get_credentials_from_session()
    if creds and creds.valid:
        return creds

    oauth_cfg = get_google_oauth_config()
    redirect_uri = oauth_cfg["redirect_uri"]

    code = get_query_param("code")

    # 1) Pas de code → on propose de se connecter
    if not code:
        flow = build_flow(redirect_uri)
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        st.session_state["oauth_state"] = state

        st.info("Tu n'es pas encore connecté à ton compte Google.")
        st.link_button("🔐 Se connecter avec Google", auth_url)
        st.stop()

    # 2) On revient de Google avec un code → on échange contre un token
    saved_state = st.session_state.get("oauth_state")
    flow = build_flow(redirect_uri)
    if saved_state:
        flow.state = saved_state

    try:
        flow.fetch_token(code=code)
    except Exception as e:
        st.error(f"Erreur pendant l'échange du code OAuth : {e}")
        st.stop()

    creds = flow.credentials
    store_credentials_in_session(creds)

    # Nettoyage des query params (enlève ?code=... de l'URL)
    clear_query_params()

    return creds


def get_gmail_service():
    """
    Renvoie un service Gmail authentifié, en forçant l'auth si besoin.
    100% web, pas de fichier local.
    """
    creds = ensure_logged_in_and_get_credentials()
    if not creds:
        st.stop()
    return build("gmail", "v1", credentials=creds)


def list_messages(service, query: str = "", max_results: int = 20) -> List[Dict[str, Any]]:
    """
    Liste des messages (id + infos) selon une requête Gmail.
    Ex: "is:unread", "from:client", "subject:TVA"
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
    api_key = st.secrets.get("OPENAI_API_KEY")
    if not api_key:
        st.error(
            "Clé OpenAI manquante.\n\n"
            "Ajoute-la dans les secrets Streamlit :\n"
            'OPENAI_API_KEY = "sk-..."\n'
        )
        st.stop()
    return OpenAI(api_key=api_key)


def summarize_email(email_body: str, language: str = "fr") -> str:
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
                    f"avec une liste à puces pour les actions à faire :\n\n"
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
    client = get_openai_client()

    prompt = (
        f"Tu es expert-comptable et tu rédiges une réponse email.\n\n"
        f"Sujet du mail reçu : {email_subject}\n\n"
        f"Contenu du mail reçu :\n{email_body}\n\n"
        f"Rédige une réponse en {language}, avec un ton {tone}, clair et structuré, "
        f"en restant réaliste (ne promets pas des choses impossibles). "
        f"Ne commence pas directement par 'Bonjour' dans ton texte, "
        f"la formule de politesse sera ajoutée après."
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
    client = get_openai_client()
    audio_file = io.BytesIO(audio_bytes)
    audio_file.name = "message.wav"

    transcript = client.audio.transcriptions.create(
        model="whisper-1",
        file=audio_file,
        response_format="text",
    )

    if isinstance(transcript, str):
        return transcript
    return getattr(transcript, "text", str(transcript))


def interpret_voice_instruction(transcribed_text: str) -> str:
    client = get_openai_client()

    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "Tu aides un expert-comptable à gérer sa boîte mail Gmail. "
                    "On te fournit une instruction dictée par la voix (déjà transcrite). "
                    "Réponds avec un plan d'action clair, sans exécuter d'actions réelles."
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

st.set_page_config(page_title="Assistant Gmail IA (web)", page_icon="📧", layout="wide")

st.title("📧 Assistant Gmail IA – 100% Web")

st.markdown(
    """
Cette app tourne **sur Streamlit Cloud** et utilise :

- 🔐 OAuth Google (type **Web**) pour accéder à *ton* Gmail (lecture seule)
- 🤖 OpenAI pour résumer et proposer des réponses
- 🎙 Un message vocal pour piloter l'assistant

Les tokens Google restent en mémoire de session (pas de fichier local).
"""
)

# --- Auth Google obligatoire avant de continuer ---
gmail_service = get_gmail_service()

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
"""
)

audio_file = st.audio_input("Enregistre un message vocal")

if audio_file is not None:
    st.audio(audio_file)

    if st.button("🧠 Transcrire et envoyer à l'assistant"):
        audio_bytes = audio_file.getvalue()

        with st.spinner("Transcription du message vocal..."):
            transcript_text = transcribe_audio(audio_bytes)

        st.markdown("#### Texte transcrit")
        st.write(transcript_text)

        with st.spinner("Interprétation par l'assistant..."):
            interpretation = interpret_voice_instruction(transcript_text)

        st.markdown("#### Réponse de l'assistant")
        st.write(interpretation)
