"""Trousseau du code de la consigne signée : clés PUBLIQUES et numéro de génération (spec consigne, § 3.3).

Trousseau réel de la consigne signée, génération 0 : clés de la cérémonie des clés du 2026-11-15 (PC Gamer, 20:58).
`CLES_DE_TEST = False` ; `tools/consigne.py signer` accepte ce trousseau. Les clés d'essai (graines dans `tests/consigne_outils.py`)
ne servent qu'aux tests.

Rien de secret ici. Une clé publique = ses 32 octets bruts Ed25519 en base64url sans remplissage (43 caractères).
"""

CLES_DE_TEST = False

# Génération du trousseau : 0 pour le premier exe public ; une relève de génération r installe r (spec § 3.3).
GENERATION = 0

# Clés de la cérémonie des clés du 2026-11-15 (PC Gamer, 20:58 ; les clés du message de 20:41 sont annulées).
CLES = {
    "consigne": {"C1": "581hsu1PQhkaLdMkbi47YGGHPnkZGpOSpiOo0wCuvs8"},
    "fraicheur": {"F1": "aphT1YAKK0FoIjrVH30K-MJ1oTH9_MMn8jjLu5HfT-c"},
    "secours": {"S1": "HvRlTxD1u6UmvEkQaTsGvsJ086Ij0vuYS6rUhr16RmQ"},
}

# Toutes les révocations connues à la fabrication de cet exe (une clé révoquée n'est plus acceptée, nulle part).
REVOQUEES_CODE = ()

# Plancher des numéros de consigne connu à la fabrication (0 : aucun).
N_MIN_CODE = 0

# Adresses par défaut : le site (recopie du miroir) puis le miroir GitHub (spec § 5.3, § 7.2).
ADRESSES_PAR_DEFAUT = (
    "https://pokerleakagent.com/wp-json/pla/v1/consigne",
    "https://pokerleakagent.github.io/consigne.json",
)
