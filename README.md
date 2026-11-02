# password-toolkit

Deux petits outils en ligne de commande, en Python (bibliothèque standard uniquement), autour de la sécurité des mots de passe :

- **`passcheck.py`** estime la robustesse d'un mot de passe et explique ses points faibles ;
- **`passgen.py`** génère des mots de passe aléatoires avec le module `secrets`.

Projet pédagogique réalisé pour comprendre ce qui rend un mot de passe fort, et pourquoi.

## Utilisation

Python 3.8 ou plus récent (`python3` sous Linux/macOS, `python` sous Windows).

```bash
python3 passgen.py -l 20 --no-symbols
# xTx5AMu4XN2m92vbYPCL
# Entropie estimée : 116.1 bits

python3 passcheck.py
# Mot de passe à tester (saisie masquée) :
# Niveau : très faible (≈ 10.0 bits, estimation indicative)
# Points faibles :
#   - trop court (moins de 12 caractères)
#   - fait partie des mots de passe les plus courants
#   - contient une suite prévisible (abcd, 1234, azerty...)
```

## Concepts illustrés

- **Entropie** : un mot de passe aléatoire de longueur *L* sur un alphabet de *N* caractères vaut environ `L × log2(N)` bits. La longueur compte plus que la complexité apparente.
- **Mots de passe courants et suites prévisibles** (`azerty`, `1234`) : un attaquant les essaie en premier, leur robustesse réelle est donc très faible, quelle que soit leur longueur théorique.
- **`secrets` plutôt que `random`** : `random` est prévisible, `secrets` s'appuie sur le générateur cryptographique du système.
- **Saisie masquée** (`getpass`) : le mot de passe n'est jamais passé en argument de commande, donc il ne reste pas dans l'historique du terminal.

## Tests

```bash
python3 -m unittest -v
```

## Limites

L'estimation est volontairement simple : elle ne remplace pas un vrai outil comme [zxcvbn](https://github.com/dropbox/zxcvbn), et la liste de mots de passe courants est très courte. Ne saisissez pas ici un mot de passe que vous utilisez réellement ailleurs, par principe.

## Pistes d'amélioration

- Utiliser une liste de mots de passe courants plus large (fichier externe).
- Vérifier une fuite connue via l'API *Pwned Passwords* (méthode k-anonymity : seuls 5 caractères du hash SHA-1 sont envoyés).
- Générer des phrases de passe (méthode Diceware).
- Ajouter une petite interface web en JavaScript.

## Licence

MIT, voir [LICENSE](LICENSE).

---

*Réalisé avec l'aide de Claude (IA), relu et testé par l'auteur.*
