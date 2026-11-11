"""Trousseau du code de la consigne signée : clés PUBLIQUES et numéro de génération (spec consigne, § 3.3).

!!! CLES DE TEST !!!  `CLES_DE_TEST = True` : ces trois clés publiques sont celles d'un trousseau d'essai. Leurs clés privées
ne vivent que dans `tests/consigne_outils.py`. Les vraies clés viendront de la cérémonie des clés (spec § 10.3) ; elles
remplaceront ces valeurs, avec `GENERATION = 0` et `CLES_DE_TEST = False`. `tools/consigne.py signer` refusera un
trousseau marqué de test (lot D) ; l'app ne le refuse pas, car elle ne signe rien.

Rien de secret ici. Une clé publique = ses 32 octets bruts Ed25519 en base64url sans remplissage (43 caractères).
"""

CLES_DE_TEST = True

# Génération du trousseau : 0 pour le premier exe public ; une relève de génération r installe r (spec § 3.3).
GENERATION = 0

CLES = {
    "consigne": {"C1": "ZIE6nagg8ACATY5VtK8RaWYXJeXp7Ykdhq83lRUH2oI"},
    "fraicheur": {"F1": "36RNejo0RbxSosUi-w2RhaLgtef5ol7sb7P3wAJjYy8"},
    "secours": {"S1": "c10D82A7FG-DeoDU0K-69UgaZ4GOunRv5zV8vrqas4M"},
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
