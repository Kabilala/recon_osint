
import os
import re
import requests
import subprocess
from datetime import datetime

# === CONFIGURATION ===
DOMAIN = "target.com"
JS_URLS = [
    "https://xxxxxxxxxxx.js",
    ,
]
KEYWORDS = ["token", "auth", "callback", "redirect", "innerHTML", "eval", "setTimeout", "setInterval"]
REGEXES = {
    "JWT": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+",
    "API Key": r"api_key\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}"
}
OUTDIR = "ultimate_recon_output"
os.makedirs(OUTDIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
combined_js = os.path.join(OUTDIR, "combined.js")
extracted_links = os.path.join(OUTDIR, "extracted_links.txt")
sensitive_keywords = os.path.join(OUTDIR, "sensitive_keywords.txt")
regex_secrets = os.path.join(OUTDIR, "regex_secrets.txt")
httpx_results = os.path.join(OUTDIR, "httpx_results.txt")
puppeteer_output = os.path.join(OUTDIR, "puppeteer_output.txt")
github_dorks_path = os.path.join(OUTDIR, "github_dorks.txt")
report_path = os.path.join(OUTDIR, f"rapport_final_{timestamp}.md")
js_list_file = os.path.join(OUTDIR, "js_urls.txt")
nuclei_templates = os.path.expanduser("~/nuclei-templates/")
burp_export_file = os.path.join(OUTDIR, "burp_targets.txt")
ffuf_wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"

def github_dorking(domain):
    print("[*] GitHub Dorking...")
    dorks = [
        f'"{domain}"',
        f'"{domain}" AND "apikey"',
        f'"{domain}" AND "token"',
        f'"{domain}" AND "password"',
        f'"{domain}" AND "aws_access_key_id"'
    ]
    with open(github_dorks_path, "w") as out:
        for dork in dorks:
            out.write(f"https://github.com/search?q={dork.replace(' ', '+')}&type=code\n")
    print("[+] Dorks GitHub générés ✅")

def download_js():
    print("[*] Téléchargement des JS...")
    headers = {"User-Agent": "Mozilla/5.0"}
    with open(combined_js, "w", encoding="utf-8") as fout, open(js_list_file, "w") as jslist:
        for url in JS_URLS:
            try:
                r = requests.get(url, timeout=10, headers=headers)
                r.raise_for_status()
                fout.write(r.text + "\n")
                jslist.write(url + "\n")
                print(f"[+] {url}")
            except Exception as e:
                print(f"[-] Échec : {url} - {e}")

def extract_endpoints():
    print("[*] Extraction des endpoints...")
    with open(combined_js, "r", encoding="utf-8") as f:
        data = f.read()
    endpoints = sorted(set(re.findall(r"https?://[^\s'\"<>]+", data)))
    with open(extracted_links, "w", encoding="utf-8") as f:
        for ep in endpoints:
            f.write(ep + "\n")
    return data, endpoints

def find_sensitive_keywords(data):
    print("[*] Recherche de mots-clés sensibles...")
    with open(sensitive_keywords, "w", encoding="utf-8") as out:
        for kw in KEYWORDS:
            matches = re.findall(rf".{{0,80}}{kw}.{{0,80}}", data, flags=re.IGNORECASE)
            if matches:
                out.write(f"\n## 🔎 Mot-clé : `{kw}`\n```js\n")
                for m in matches:
                    out.write(m.strip() + "\n")
                out.write("```\n")

def scan_secrets_regex():
    print("[*] Scan des secrets (regex)...")
    with open(combined_js, "r", encoding="utf-8") as f:
        content = f.read()
    with open(regex_secrets, "w") as out:
        for label, pattern in REGEXES.items():
            matches = re.findall(pattern, content)
            if matches:
                out.write(f"\n## {label} FOUND\n")
                for m in matches:
                    out.write(f"{m}\n")

def run_httpx():
    print("[*] Vérification HTTPX...")
    if os.path.getsize(extracted_links) == 0:
        print("[!] Aucun endpoint trouvé.")
        with open(httpx_results, "w") as f:
            f.write("Aucun endpoint détecté.\n")
    else:
        cmd = f"httpx -q -l {extracted_links} -o {httpx_results}"
        subprocess.run(cmd, shell=True, check=True)

def puppeteer_render():
    print("[*] Puppeteer rendering...")
    script = f'''
const puppeteer = require('puppeteer');
const fs = require('fs');
(async () => {{
    const browser = await puppeteer.launch({{headless: true}});
    const page = await browser.newPage();
    const urls = fs.readFileSync("{extracted_links}", 'utf8').split('\n');
    for (const url of urls) {{
        if (!url) continue;
        try {{
            await page.goto(url, {{waitUntil: 'networkidle2'}});
            const scripts = await page.$$eval('script[src]', tags => tags.map(tag => tag.src));
            fs.appendFileSync("{puppeteer_output}", `URL: ${{url}}\nScripts:\n${{scripts.join('\n')}}\n\n`);
        }} catch (e) {{
            fs.appendFileSync("{puppeteer_output}", `URL: ${{url}}\nError: ${{e}}\n\n`);
        }}
    }}
    await browser.close();
}})();
'''
    with open("puppeteer_scraper.js", "w") as f:
        f.write(script)
    subprocess.run(["node", "puppeteer_scraper.js"])

def fuzz_with_ffuf():
    print("[*] Lancement de ffuf...")
    os.makedirs(f"{OUTDIR}/ffuf", exist_ok=True)
    with open(extracted_links) as f:
        for i, url in enumerate(f):
            url = url.strip()
            if url.startswith("http"):
                ffuf_output = f"{OUTDIR}/ffuf/fuzz_{i}.json"
                subprocess.run([
                    "ffuf", "-u", f"{url}?FUZZ=test", "-w", ffuf_wordlist,
                    "-mc", "200,403", "-t", "25", "-of", "json", "-o", ffuf_output
                ])

def scan_with_nuclei():
    print("[*] Scan avec Nuclei...")
    nuclei_output = os.path.join(OUTDIR, f"nuclei_results_{timestamp}.txt")
    cmd = f"cat {extracted_links} | httpx -silent | nuclei -t {nuclei_templates} -o {nuclei_output}"
    subprocess.run(cmd, shell=True)

def suspicious_link_filter():
    print("[*] Filtrage des liens suspects (SSRF, LFI, etc)...")
    patterns = ["ssrf", "lfi", "file=", "url=", "path=", "xss", "redirect", "token", "callback"]
    with open(extracted_links, "r") as f, open(f"{OUTDIR}/suspicious_links.txt", "w") as out:
        for line in f:
            if any(p in line.lower() for p in patterns):
                out.write(line)

def export_for_burp():
    print("[*] Export vers BurpSuite...")
    with open(extracted_links, "r") as f, open(burp_export_file, "w") as out:
        for link in f:
            if link.startswith("http"):
                out.write(link)

def generate_report(endpoints):
    print("[*] Génération du rapport final...")
    with open(report_path, "w", encoding="utf-8") as rpt:
        rpt.write(f"# 🛡 Rapport Recon - {DOMAIN}\n")
        rpt.write(f"🕒 Généré : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        rpt.write("## Endpoints\n" + "\n".join(f"- {ep}" for ep in endpoints))
        rpt.write("\n\n## Mots-clés sensibles\n")
        rpt.write(open(sensitive_keywords).read())
        rpt.write("\n\n## Secrets détectés\n")
        rpt.write(open(regex_secrets).read())
        rpt.write("\n\n## HTTPX\n```\n")
        rpt.write(open(httpx_results).read() + "\n```")
        rpt.write("\n\n## Puppeteer\n```\n")
        rpt.write(open(puppeteer_output).read() + "\n```")
        rpt.write("\n\n## GitHub Dorks\n")
        rpt.write(open(github_dorks_path).read())

if __name__ == "__main__":
    download_js()
    js_data, endpoints = extract_endpoints()
    find_sensitive_keywords(js_data)
    scan_secrets_regex()
    run_httpx()
    github_dorking(DOMAIN)
    puppeteer_render()
    fuzz_with_ffuf()
    suspicious_link_filter()
    scan_with_nuclei()
    export_for_burp()
    generate_report(endpoints)
    print("\n🎯 Ultimate Recon terminé.")
