# Module d'Analyse SSL/TLS

Ce projet contient un module Python autonome (`ssl_tls_analyzer.py`) pour effectuer une analyse de sécurité SSL/TLS sur un hôte donné. Il peut être utilisé soit comme un outil en ligne de commande, soit comme une bibliothèque importable dans d'autres programmes.

## Fonctionnalités

- **Analyse du Certificat :** Récupère et affiche les détails du certificat SSL/TLS, y compris le sujet, l'émetteur et la date d'expiration.
- **Scan des Protocoles :** Détecte les versions de TLS supportées par le serveur (TLSv1 à TLSv1.3).
- **Détection des Protocoles Faibles :** Signale si des protocoles obsolètes et non sécurisés (TLSv1, TLSv1.1) sont activés.

---

## Installation

Avant d'utiliser le module, installez les dépendances nécessaires :

```bash
pip install -r requirements.txt
```

---

## Comment utiliser le code

Vous pouvez utiliser ce module de deux manières : directement depuis la ligne de commande ou en l'important dans votre propre code Python.

### 1. Utilisation en Ligne de Commande (CLI)

Pour analyser un site web, exécutez le script en lui passant un nom d'hôte :

```bash
python3 ssl_tls_analyzer.py google.com
```

**Exemple de sortie :**

```
--- Analyzing certificate for: google.com ---
  Subject: *.google.com
  Issuer: WR2
  Expires on: 2026-01-05T08:37:32
  Expired: No

--- Scanning supported protocols for: google.com ---
  TLSv1: Not Supported
  TLSv1.1: Not Supported
  TLSv1.2: Supported
  TLSv1.3: Supported

[+] No weak protocols detected.
```

### 2. Utilisation comme Bibliothèque

La fonction principale à importer est `analyze_host(hostname)`. Elle prend un nom d'hôte en argument et retourne un dictionnaire contenant l'ensemble des résultats de l'analyse.

Voici un exemple d'intégration dans un autre script Python :

```python
from ssl_tls_analyzer import analyze_host
import json

def check_website_security(hostname):
    print(f"Analyse de {hostname}...")

    results = analyze_host(hostname)

    # Vous pouvez maintenant utiliser les résultats comme vous le souhaitez
    if results['certificate_details'].get('is_expired'):
        print(f"[!] Le certificat pour {hostname} est expiré !")

    if results['protocol_analysis']['weak_protocols_found']:
        print(f"[!] Des protocoles faibles ont été détectés : {results['protocol_analysis']['weak_protocols_found']}")

    # Afficher le rapport complet au format JSON
    print("\nRapport complet :")
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    check_website_security('github.com')

```

---

## Comment tester le module

Pour garantir la fiabilité du module, une suite de tests unitaires a été créée. Ces tests utilisent des simulations (`mocks`) pour valider la logique du code sans effectuer de réelles connexions réseau.

Pour lancer les tests, exécutez la commande suivante depuis la racine du projet :

```bash
python3 test_ssl_tls_analyzer.py
```

**Exemple de sortie en cas de succès :**
```
....
----------------------------------------------------------------------
Ran 4 tests in 0.081s

OK
```
