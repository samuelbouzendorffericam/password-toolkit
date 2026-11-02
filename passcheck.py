#!/usr/bin/env python3
"""passcheck : estime la robustesse d'un mot de passe (outil pédagogique).

Le mot de passe est saisi de façon masquée (getpass) : il n'apparaît ni à
l'écran, ni dans l'historique du terminal, ni dans la liste des processus.
"""
import argparse
import getpass
import math
import re
import string
from dataclasses import dataclass, field

# Petit échantillon de mots de passe très courants (liste volontairement courte).
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "1234567890", "111111", "000000", "123123",
    "password", "password1", "motdepasse", "motdepasse1", "azerty", "azerty123",
    "azertyuiop", "qwerty", "qwerty123", "abc123", "iloveyou", "admin", "welcome",
    "letmein", "monkey", "dragon", "football", "soleil", "doudou", "chocolat",
    "marseille", "bonjour", "superman",
}
KEYBOARD_PATTERNS = ("azerty", "qwerty", "qsdfgh", "wxcvbn", "123456", "654321")
# (seuil en bits, libellé) : en dessous du seuil, on prend le libellé correspondant.
LEVELS = [(28, "très faible"), (36, "faible"), (60, "moyen"), (80, "fort")]


@dataclass
class Result:
    bits: float
    level: str
    problems: list = field(default_factory=list)


def charset_size(password: str) -> int:
    """Taille de l'alphabet que l'attaquant devrait explorer (estimation)."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    if any(not (c.isascii() and (c.isalnum() or c in string.punctuation)) for c in password):
        size += 30  # accents, espaces, autres caractères
    return max(size, 1)


def has_run(text: str, n: int = 4) -> bool:
    """Vrai si le texte contient n caractères consécutifs (abcd, 1234, 4321...)."""
    t = text.lower()
    up = down = 1
    for prev, cur in zip(t, t[1:]):
        diff = ord(cur) - ord(prev)
        up = up + 1 if diff == 1 else 1
        down = down + 1 if diff == -1 else 1
        if up >= n or down >= n:
            return True
    return False


def effective_length(password: str) -> int:
    """Longueur après réduction des répétitions (aaaa -> a)."""
    return len(re.sub(r"(.)\1{2,}", r"\1", password))


def evaluate(password: str) -> Result:
    if not password:
        return Result(0.0, LEVELS[0][1], ["mot de passe vide"])

    problems = []
    lower = password.lower()
    is_common = lower in COMMON_PASSWORDS
    has_pattern = any(p in lower for p in KEYBOARD_PATTERNS) or has_run(password)
    has_repeat = re.search(r"(.)\1{2,}", password) is not None

    if len(password) < 12:
        problems.append("trop court (moins de 12 caractères)")
    if is_common:
        problems.append("fait partie des mots de passe les plus courants")
    if has_pattern:
        problems.append("contient une suite prévisible (abcd, 1234, azerty...)")
    if has_repeat:
        problems.append("contient des caractères répétés (aaa)")
    if password.isalpha() or password.isdigit():
        problems.append("un seul type de caractères (lettres seules ou chiffres seuls)")

    bits = effective_length(password) * math.log2(charset_size(password))
    if has_pattern:
        bits *= 0.6
    if is_common:
        bits = min(bits, 10.0)

    level = "très fort"
    for threshold, label in LEVELS:
        if bits < threshold:
            level = label
            break
    return Result(round(bits, 1), level, problems)


def main() -> None:
    parser = argparse.ArgumentParser(description="Estime la robustesse d'un mot de passe.")
    parser.parse_args()
    password = getpass.getpass("Mot de passe à tester (saisie masquée) : ")
    result = evaluate(password)
    print(f"Niveau : {result.level} (≈ {result.bits} bits, estimation indicative)")
    if result.problems:
        print("Points faibles :")
        for p in result.problems:
            print(f"  - {p}")
    else:
        print("Aucun point faible détecté par ces règles simples.")


if __name__ == "__main__":
    main()
