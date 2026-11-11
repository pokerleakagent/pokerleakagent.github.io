"""Surveillance du miroir et du site (spec docs/superpowers/specs/2026-11-11-consigne-signee-fin-de-beta-design.md, § 7.2, étape 4).

Lancé par `bulletin.yml` après la fabrication, à chaque passage (même si rien n'a été publié). Dossier de travail `outils/`.
Lit le miroir et le site comme l'app (User-Agent fixe, sans cookie). Alerte = un ticket « ALERTE consigne » du dépôt
(ouvert ou complété) et code de sortie 1 (courriel d'échec en plus). Le passage précédent est gardé dans `etat/surveillance.json`
(commité par la tâche) pour le critère « site muet à deux passages de suite ».

Codes : 0 = rien à signaler ; 1 = alerte (ticket ouvert ou complété) ; 2 = configuration.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

RACINE_DEPOT = Path(__file__).resolve().parent.parent     # le dépôt du miroir ; `outils/` est le dossier de travail

from pla_commun import consigne as c  # noqa: E402  (outils/pla_commun, copie du dépôt principal)

URL_MIROIR = "https://pokerleakagent.github.io/consigne.json"
URL_SITE = "https://pokerleakagent.com/wp-json/pla/v1/consigne"
REPO = "pokerleakagent/pokerleakagent.github.io"
TITRE = "ALERTE consigne"
ETAT = RACINE_DEPOT / "etat" / "surveillance.json"
ESSAIS_SITE = 3                       # 3 essais espacés d'une minute, lors d'un passage (spec § 7.2)
PAUSE_S = 60
ECART_COMMIT = timedelta(hours=3)     # le site recopie toutes les heures : au-delà, un écart est une panne
SEUIL_JOURS = 10                      # moins de 10 jours de tickets : alerte (spec § 7.2)


class Injoignable(Exception):
    """Pas de réponse (réseau, délai)."""


class Absent(Exception):
    """Réponse 404 : pas de bulletin."""


class Invalide(Exception):
    """Un bulletin qui ne se vérifie pas (ou aucun ticket valide)."""


@dataclass(frozen=True)
class Resume:
    n: int
    dernier: date      # dernier jour de ticket valide, lié à la consigne


def resumer(octets: bytes, modele, maintenant: datetime, jour: date) -> Resume:
    """Vérifie un bulletin avec le code de l'app et en tire le n° de consigne et le dernier ticket valide."""
    try:
        b = c.lire_bulletin(octets)
        t = c.trousseau_du_code(modele)
        res = c.evaluer_bulletin(None, b, maintenant, jour_site=jour, trousseau_code=t)
    except c.JetonInvalide as erreur:
        raise Invalide(str(erreur)) from erreur
    if res.etat.consigne is None:
        raise Invalide("aucune consigne valide")
    consigne = res.etat.consigne
    jours = []
    for jeton in b.tickets:
        try:
            ticket = c.lire_ticket(jeton, res.etat.trousseau)
        except c.JetonInvalide:
            continue
        if ticket.n == consigne.n and ticket.h == c.empreinte(consigne.jeton):
            jours.append(ticket.jour)
    if not jours:
        raise Invalide("aucun ticket valide lié à la consigne")
    return Resume(consigne.n, max(jours))


def analyser(aujourd_hui: date, maintenant: datetime, miroir, site, commit_consigne, precedent: dict):
    """Les raisons d'alerter (liste, vide = rien) et le nouvel état du passage. Fonction pure.

    `site` : un Resume, ou « muet » (3 essais sans réponse), « absent » (pas de bulletin), « invalide » (ne se vérifie pas)."""
    raisons = []
    if miroir is None:
        raisons.append("le miroir ne publie aucun bulletin valide")
    else:
        reste = (miroir.dernier - aujourd_hui).days
        if reste < SEUIL_JOURS:
            raisons.append(f"le miroir n'a plus que {reste} jour(s) de tickets (moins de {SEUIL_JOURS})")
    if site == "muet":
        if precedent.get("site_muet"):
            raisons.append("le site ne répond pas (3 essais, deux passages de suite)")
    elif site == "absent":
        raisons.append("le site ne publie aucun bulletin")
    elif site == "invalide":
        raisons.append("le site publie un bulletin qui ne se vérifie pas")
    elif miroir is not None:
        if site.n != miroir.n and (commit_consigne is None or maintenant - commit_consigne > ECART_COMMIT):
            raisons.append(f"le site affiche la consigne n° {site.n}, le miroir la n° {miroir.n} "
                           "(depuis plus de 3 heures)")
        if site.dernier < miroir.dernier - timedelta(days=1):
            raisons.append(f"le site a {(miroir.dernier - site.dernier).days} jours de retard sur les tickets du miroir")
    nouvel_etat = {"site_muet": site == "muet", "passage": maintenant.astimezone(timezone.utc).isoformat()}
    return raisons, nouvel_etat


def passer(*, modele, fetch, alerte, attendre, maintenant: datetime, commit_consigne, etat_fichier: Path) -> int:
    """Un passage complet. `fetch(url)` renvoie (octets, date du site) ou lève Injoignable / Absent ; `alerte(texte)`
    ouvre ou complète le ticket. Tout ce qui sort du poste est injecté (les tests le remplacent)."""
    jour = maintenant.astimezone(timezone.utc).date()
    precedent = json.loads(etat_fichier.read_text(encoding="utf-8")) if etat_fichier.exists() else {}
    miroir = _miroir(fetch, modele, maintenant, jour)
    site = _site(fetch, modele, maintenant, jour, attendre)
    raisons, nouvel_etat = analyser(jour, maintenant, miroir, site, commit_consigne, precedent)
    etat_fichier.parent.mkdir(parents=True, exist_ok=True)
    temporaire = etat_fichier.with_name(etat_fichier.name + ".tmp")
    temporaire.write_text(json.dumps(nouvel_etat, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    os.replace(temporaire, etat_fichier)
    if raisons:
        alerte(f"{TITRE} : " + " ; ".join(raisons) + f" (passage du {maintenant:%Y-%m-%d %H:%M} UTC)")
        return 1
    return 0


def _miroir(fetch, modele, maintenant, jour):
    try:
        octets, _ = fetch(URL_MIROIR)
    except (Injoignable, Absent):
        return None
    try:
        return resumer(octets, modele, maintenant, jour)
    except Invalide:
        return None


def _site(fetch, modele, maintenant, jour, attendre):
    for essai in range(ESSAIS_SITE):
        try:
            octets, jour_site = fetch(URL_SITE)
        except Absent:
            return "absent"
        except Injoignable:
            if essai < ESSAIS_SITE - 1:
                attendre(PAUSE_S)
            continue
        try:
            return resumer(octets, modele, maintenant, jour_site or jour)
        except Invalide:
            return "invalide"
    return "muet"


def lire_adresse(url: str):
    """Lecture réelle : https, User-Agent fixe, 5 s, 16 385 octets au plus, en-tête Date."""
    from email.utils import parsedate_to_datetime
    requete = urllib.request.Request(url, headers={"User-Agent": "PokerLeakAgent", "Accept": "application/json",
                                                    "Accept-Encoding": "identity", "Connection": "close"})
    try:
        with urllib.request.urlopen(requete, timeout=5) as reponse:
            octets = reponse.read(c.BULLETIN_MAX + 1)
            entete = reponse.headers.get("Date")
    except urllib.error.HTTPError as erreur:
        if erreur.code == 404:
            raise Absent(url) from erreur
        raise Injoignable(url) from erreur
    except (urllib.error.URLError, TimeoutError, OSError) as erreur:
        raise Injoignable(url) from erreur
    jour_site = None
    if entete:
        try:
            jour_site = parsedate_to_datetime(entete).astimezone(timezone.utc).date()
        except (TypeError, ValueError):
            jour_site = None
    return octets, jour_site


def date_du_dernier_commit(depot: Path):
    sortie = subprocess.run(["git", "-C", str(depot), "log", "-1", "--format=%cI", "--", "source/consigne.txt"],
                            capture_output=True, text=True)
    if sortie.returncode != 0 or not sortie.stdout.strip():
        return None
    return datetime.fromisoformat(sortie.stdout.strip()).astimezone(timezone.utc)


def alerte_github(texte: str) -> None:
    """Un seul ticket « ALERTE consigne » ouvert : on le complète s'il existe, sinon on l'ouvre (GitHub envoie le courriel)."""
    liste = subprocess.run(["gh", "issue", "list", "--repo", REPO, "--state", "open", "--search", f"{TITRE} in:title",
                            "--json", "number"], capture_output=True, text=True, check=True).stdout
    ouverts = json.loads(liste or "[]")
    if ouverts:
        subprocess.run(["gh", "issue", "comment", str(ouverts[0]["number"]), "--repo", REPO, "--body", texte],
                       check=True)
    else:
        subprocess.run(["gh", "issue", "create", "--repo", REPO, "--title", TITRE, "--body", texte], check=True)


def main() -> int:
    from pla_commun import consigne_cles
    maintenant = datetime.now(timezone.utc)
    return passer(modele=consigne_cles, fetch=lire_adresse, alerte=alerte_github, attendre=time.sleep,
                  maintenant=maintenant, commit_consigne=date_du_dernier_commit(RACINE_DEPOT), etat_fichier=ETAT)


if __name__ == "__main__":
    raise SystemExit(main())
