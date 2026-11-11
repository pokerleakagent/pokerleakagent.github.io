"""Fabrique le bulletin publié par la tâche GitHub du miroir (spec docs/superpowers/specs/2026-11-11-consigne-signee-fin-de-beta-design.md, § 7.2, étapes 1 et 2).

Lancé par `bulletin.yml` avec `outils/` comme dossier de travail. Ne dépend que de Python, de `cryptography` et de la copie
`outils/pla_commun/` (même chemin d'import que le dépôt principal). Ne contient aucun secret.

Entrées (dans le dépôt du miroir) : `source/consigne.txt` (la consigne), `source/releves.txt` (facultatif), `consigne.json`
(le dernier bulletin publié, facultatif). Secret : variable d'environnement `CLE_FRAICHEUR` (graine Ed25519 de 32 octets,
base64url), lue SEULEMENT si une consigne existe.

Sortie : `consigne.json`, écrit seulement si les deux vérifications passent (état vide, puis continuité). Codes : 0 = publié,
ou « pas encore de consigne » (arrêt propre, rien à faire) ; 1 = refus, rien n'est écrit ; 2 = configuration.
"""
from __future__ import annotations

import argparse
import base64
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pla_commun import consigne as c

DOSSIER_OUTILS = Path(__file__).resolve().parent
RACINE_DEPOT = DOSSIER_OUTILS.parent
PLAGE_TICKETS = range(-3, 14)          # J−3 à J+13 : 17 tickets (spec § 3.4)
VAR_SECRET = "CLE_FRAICHEUR"
PAS_ENCORE = "pas encore de consigne : rien à publier (le bulletin précédent, s'il existe, reste en ligne)"


class Arret(Exception):
    """Un refus (rien n'est écrit) : le message ne contient jamais de secret."""


def _b64(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def tickets(jour: date, n: int, jeton_consigne: str, priv: Ed25519PrivateKey, cle_id: str) -> list:
    """Les 17 tickets de J−3 à J+13, tous liés à la consigne exacte (n et empreinte du jeton)."""
    lien = c.empreinte(jeton_consigne)
    return [c.signer(c.PREFIXE_TICKET, {"v": c.VERSION_JETON, "produit": c.PRODUIT,
                                        "jour": (jour + timedelta(days=d)).isoformat(), "n": n, "h": lien,
                                        "cle": cle_id}, priv)
            for d in PLAGE_TICKETS]


def _trousseau_publie(modele, releves: list) -> c.Trousseau:
    depart = c.trousseau_du_code(modele)
    final, acceptees, _ = c.appliquer_releves(depart, 0, releves)
    if len(acceptees) != len(releves):
        raise Arret("une relève publiée ne se vérifie pas avec le trousseau du code")
    return final


def _cle_fraicheur(valeur: str, t: c.Trousseau):
    """La clé du secret doit être une clé fraîcheur utilisable du trousseau (sinon refus, sans rien afficher)."""
    try:
        brut_graine = base64.urlsafe_b64decode(valeur + "=" * (-len(valeur) % 4))
    except (ValueError, TypeError) as erreur:
        raise Arret("secret : texte base64url attendu") from erreur
    if len(brut_graine) != 32:
        raise Arret("secret : 32 octets attendus")
    priv = Ed25519PrivateKey.from_private_bytes(brut_graine)
    brut = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ids = [i for i, valeur_cle in t.utilisables("fraicheur").items() if valeur_cle == brut]
    if len(ids) != 1:
        raise Arret("le secret ne correspond à aucune clé fraîcheur du trousseau")
    return priv, ids[0]


def fabriquer(consigne: str, releves: list, jour: date, priv: Ed25519PrivateKey, cle_id: str,
              precedent: bytes | None, modele) -> bytes:
    """Le bulletin (octets) si les deux vérifications passent ; sinon Arret. Pure (ni disque ni réseau)."""
    try:
        n = c.lire_consigne(consigne, _trousseau_publie(modele, releves)).n
    except c.JetonInvalide as erreur:
        raise Arret(f"la consigne ne se vérifie pas avec le trousseau du code : {erreur}") from erreur
    bulletin = {"format": c.FORMAT_BULLETIN, "releves": list(releves), "consignes": [consigne],
                "tickets": tickets(jour, n, consigne, priv, cle_id)}
    try:
        octets = c.octets_bulletin(bulletin)
        verifier(octets, precedent, modele, jour)
    except ValueError as erreur:
        raise Arret(f"bulletin refusé : {erreur}") from erreur
    return octets


def verifier(octets: bytes, precedent: bytes | None, modele, jour: date) -> None:
    """Contact réussi depuis un état vide (spec § 7.2 étape 2), puis depuis l'état de continuité (le bulletin précédent)."""
    maintenant = datetime(jour.year, jour.month, jour.day, 12, tzinfo=timezone.utc)
    t = c.trousseau_du_code(modele)
    res = c.evaluer_bulletin(None, c.lire_bulletin(octets), maintenant, jour_site=jour, trousseau_code=t)
    if not res.contact:
        raise Arret("le bulletin ne donne pas un contact réussi depuis un état vide : rien publié")
    if precedent is not None:
        etat = c.evaluer_bulletin(None, c.lire_bulletin(precedent), maintenant, jour_site=jour, trousseau_code=t).etat
        if not c.evaluer_bulletin(etat, c.lire_bulletin(octets), maintenant, jour_site=jour).contact:
            raise Arret("le bulletin ne donne pas un contact réussi depuis le bulletin précédent : rien publié")


def main(argv=None) -> int:
    parseur = argparse.ArgumentParser(description="Fabrique le bulletin du miroir (tâche GitHub).")
    parseur.add_argument("--jour", help="date UTC AAAA-MM-JJ (tests ; par défaut aujourd'hui en UTC)")
    args = parseur.parse_args(argv)
    source = RACINE_DEPOT / "source"
    consigne_fichier = source / "consigne.txt"
    consigne = consigne_fichier.read_text(encoding="utf-8").strip() if consigne_fichier.exists() else ""
    if not consigne:
        print(PAS_ENCORE)          # arrêt propre : le secret n'est pas lu
        return 0
    releves_fichier = source / "releves.txt"
    releves = [ligne.strip() for ligne in releves_fichier.read_text(encoding="utf-8").splitlines() if ligne.strip()] \
        if releves_fichier.exists() else []
    jour = date.fromisoformat(args.jour) if args.jour else datetime.now(timezone.utc).date()
    valeur = os.environ.get(VAR_SECRET)
    if not valeur:
        print("secret de la tâche absent : rien publié (vérifier le secret du dépôt)")
        return 2
    precedent_fichier = RACINE_DEPOT / "consigne.json"
    precedent = precedent_fichier.read_bytes() if precedent_fichier.exists() else None
    try:
        priv, cle_id = _cle_fraicheur(valeur, _trousseau_publie(_modele_du_code(), releves))
        octets = fabriquer(consigne, releves, jour, priv, cle_id, precedent, _modele_du_code())
    except Arret as refus:
        print(f"Refus : {refus}. Rien n'a été écrit ; le bulletin précédent reste en ligne.")
        return 1
    temporaire = RACINE_DEPOT / "consigne.json.tmp"
    temporaire.write_bytes(octets)
    os.replace(temporaire, precedent_fichier)          # un seul remplacement : jamais un bulletin à moitié écrit
    lu = c.lire_bulletin(octets)
    print(f"Bulletin publié pour le {jour.isoformat()} : {len(lu.tickets)} tickets, {len(lu.releves)} relève(s).")
    return 0


def _modele_du_code():
    from pla_commun import consigne_cles
    return consigne_cles


if __name__ == "__main__":
    raise SystemExit(main())
