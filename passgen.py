#!/usr/bin/env python3
"""passgen : génère des mots de passe aléatoires avec le module `secrets`.

`secrets` utilise le générateur aléatoire cryptographique du système, contrairement
à `random` qui est prévisible et ne doit jamais servir pour des mots de passe.
"""
import argparse
import math
import secrets
import string

AMBIGUOUS = set("O0oIl1|")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def build_classes(use_symbols: bool = True, avoid_ambiguous: bool = True) -> list:
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        classes.append(SYMBOLS)
    if avoid_ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
    return classes


def generate(length: int = 16, use_symbols: bool = True, avoid_ambiguous: bool = True) -> str:
    """Mot de passe aléatoire contenant au moins un caractère de chaque famille."""
    if length < 8:
        raise ValueError("La longueur minimale est de 8 caractères.")
    classes = build_classes(use_symbols, avoid_ambiguous)
    pool = "".join(classes)
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def entropy_bits(length: int, use_symbols: bool = True, avoid_ambiguous: bool = True) -> float:
    pool_size = len("".join(build_classes(use_symbols, avoid_ambiguous)))
    return round(length * math.log2(pool_size), 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Génère un mot de passe aléatoire.")
    parser.add_argument("-l", "--length", type=int, default=16, help="longueur (défaut : 16)")
    parser.add_argument("--no-symbols", action="store_true", help="sans caractères spéciaux")
    parser.add_argument("--allow-ambiguous", action="store_true", help="autorise O, 0, l, 1, I...")
    args = parser.parse_args()
    use_symbols = not args.no_symbols
    avoid = not args.allow_ambiguous
    print(generate(args.length, use_symbols, avoid))
    print(f"Entropie estimée : {entropy_bits(args.length, use_symbols, avoid)} bits")


if __name__ == "__main__":
    main()
