
# 🔎 Ultimate Recon

Outil d'automatisation OSINT/Recon pour applications web basé sur le domaine cible.  
Il combine plusieurs modules puissants pour extraire des endpoints, secrets, scripts dynamiques, vulnérabilités courantes et générer un rapport Markdown complet.

---

## ⚙️ Fonctionnalités

- 📥 Téléchargement de fichiers JavaScript distants
- 🔗 Extraction d’endpoints à partir des JS
- 🧪 Détection de mots-clés sensibles (`token`, `auth`, etc.)
- 🕵️ Scan de secrets avec Regex (JWT, API keys, AWS keys...)
- 🧠 Rendu JS avec Puppeteer pour obtenir les scripts dynamiques
- 🔍 GitHub Dorking automatique pour recherche de fuites publiques
- 🚀 Fuzzing des endpoints avec FFUF
- ☠️ Scan de vulnérabilités (SSRF, LFI, etc.) via Nuclei
- 🧼 Détection de patterns suspects dans les URLs
- 🛠️ Export vers BurpSuite pour exploitation manuelle
- 📄 Rapport final généré en Markdown

---

## 📦 Prérequis

Assure-toi d’avoir installé les outils suivants :

### 🐍 Python + pip

```bash
pip install -r requirements.txt
````

**Note** : crée un fichier `requirements.txt` si tu ajoutes des dépendances Python.

### 🧰 Outils externes

| Outil                      | Installation                                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `httpx`                    | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`                                           |
| `ffuf`                     | `go install github.com/ffuf/ffuf/v2@latest`                                                                  |
| `nuclei`                   | `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`                                      |
| `puppeteer`                | `npm install puppeteer`                                                                                      |
| `SecretFinder` (optionnel) | `git clone https://github.com/m4ll0k/SecretFinder.git && cd SecretFinder && pip install -r requirements.txt` |

---

## 📂 Arborescence de sortie

```
ultimate_recon_output/
│
├── combined.js                # JS combiné
├── extracted_links.txt        # Tous les endpoints extraits
├── sensitive_keywords.txt     # Mot-clés sensibles
├── regex_secrets.txt          # Secrets détectés par regex
├── puppeteer_output.txt       # Scripts dynamiques détectés
├── ffuf/                      # Résultats FFUF
├── nuclei/                    # Résultats Nuclei
├── suspicious_links.txt       # URLs suspects (LFI, SSRF, etc.)
├── github_dorks.txt           # Dorks à tester manuellement
├── burp_targets.txt           # Export brut pour BurpSuite
└── rapport_final_*.md         # Rapport Markdown complet
```

---

## ▶️ Lancer le script

```bash
python3 ultimate_recon.py
```

Le script exécutera **tout automatiquement**.

---

## 🛠 Personnalisation

* Change le domaine cible dans la variable `DOMAIN` dans `ultimate_recon.py`
* Ajoute tes propres URLs JS dans la liste `JS_URLS`
* Modifie les chemins des wordlists si besoin (`ffuf`, `nuclei` templates)

---

## 🧩 TODO

* [ ] Ajouter une CLI avec `argparse`
* [ ] Intégration Shodan/Wayback
* [ ] Ajout de scan DNS/ports avec `dnsx`, `naabu`, etc.
