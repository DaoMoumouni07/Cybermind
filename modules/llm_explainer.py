import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def explain_malware_result(prediction_result, file_name):
    features_str = "\n".join([
        f"- {k}: {v}" for k, v in prediction_result["features"].items()
    ])
    prompt = f"""Tu es expert en cybersecurite. Analyse ce resultat.
Fichier : {file_name}
Verdict : {prediction_result['label']}
Confiance : {prediction_result['confidence']}%
Proba malware : {prediction_result['proba_malware']}%
Features PE :
{features_str}
Donne : 1. Verdict clair 2. Indicateurs suspects 3. Niveau de risque 4. Action recommandee.
Reponds en francais de facon structuree."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )
    return response.choices[0].message.content

def explain_pentest_analysis(target_data, user_query):
    ports_str = "\n".join([
        f"- Port {p['port']} ({p['service']}) {p['version']}"
        for p in target_data.get("open_ports", [])
    ]) or "Aucun scan fourni"
    cves_str = "\n".join([
        f"- [{c['severity']}] {c['id']}: {c['description'][:120]}..."
        for c in target_data.get("relevant_cves", [])
    ]) or "Aucune CVE trouvee"
    prompt = f"""Tu es expert en pentesting. Analyse cette cible.
Question : {user_query}
Ports ouverts :
{ports_str}
CVEs potentielles :
{cves_str}
Donne : 1. Risques 2. Vecteurs d attaque 3. CVEs critiques 4. Outils 5. Remediations.
Reponds en francais de facon structuree."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1500
    )
    return response.choices[0].message.content