"""Consigne signée de PLA : le cœur PUR du mécanisme (lot A de la spec, §§ 3.2 à 3.6).

Spec : docs/superpowers/specs/2026-11-11-consigne-signee-fin-de-beta-design.md.

Ce module ne lit ni l'horloge, ni le disque, ni le réseau : toute date ou heure est un paramètre. Il ne lit pas
l'environnement du processus, n'importe jamais `app`, et n'importe `cryptography` que dans les fonctions qui vérifient une signature.
Il n'importe que la bibliothèque standard et `pla_commun.consigne_cles` (trousseau du code). Il est copié tel quel dans
le dépôt du miroir (§ 7.2) : il ne contient aucun secret.

Trois jetons, même forme : `<PRÉFIXE>.<charge>.<signature>`. Le message signé est `<PRÉFIXE>.<charge>` (préfixe compris),
donc une signature d'un type ne vaut jamais pour un autre :
  PLC1 = consigne (clés « consigne »), PLF1 = ticket de fraîcheur (clés « fraicheur »), PLR1 = relève (clés « secours »).

RÈGLES POUR LE LOT B (à lire avant d'écrire une ligne de stockage) :
- `lire_etat` ne vérifie PAS le scellement (`mac`) : l'appelant le vérifie AVANT et le dit par `scellement_verifie=True`.
- `fusionner(a, b)` ne sert qu'à fusionner DEUX MAGASINS FRÈRES (disque et registre, même histoire, aucun des deux
  ancêtre de l'autre). Ne jamais fusionner un état avec une copie plus ancienne de lui-même : `max_local` ne baisse que
  par un contact (`evaluer_bulletin`), et la fusion le garderait haut. Ordre imposé : fusionner les magasins entre eux,
  PUIS rejouer l'événement en mémoire sur le résultat (`evaluer_bulletin` pour un bulletin, `mettre_a_jour_horloge`
  pour l'écriture horaire).
- `evaluer_bulletin` ignore `trousseau_code` dès qu'un état est fourni (il ne sert qu'à un état vide).
- Le lot B borne la lecture HTTP à `BULLETIN_MAX + 1` octets avant `lire_bulletin`, et retire un éventuel BOM UTF-8
  avant (`lire_bulletin` refuse un BOM).
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from pla_commun import consigne_cles

VERSION_JETON = 1
PRODUIT = "tracker"
PREFIXE_CONSIGNE = "PLC1"
PREFIXE_TICKET = "PLF1"
PREFIXE_RELEVE = "PLR1"
ROLES = ("consigne", "fraicheur", "secours")
ROLE_DU_PREFIXE = {PREFIXE_CONSIGNE: "consigne", PREFIXE_TICKET: "fraicheur", PREFIXE_RELEVE: "secours"}
JETON_MAX = 2048
BULLETIN_MAX = 16384
MESSAGE_MAX = 300
ADRESSES_MAX = 4
ADRESSE_MAX = 200
CONSIGNES_LUES_MAX = 20      # consignes lues par bulletin (au-delà : ignorées et journalisées)
TICKETS_LUS_MAX = 20
RELEVES_MAX = 4              # relèves lues par bulletin (plus de 4 : la liste entière est ignorée)
RELEVES_GARDEES_MAX = 8      # relèves gardées dans l'état local
BORNE_ENTIER = 2 ** 31       # tout entier d'un jeton est < 2**31
JOURS_FRAIS = 3              # un ticket est frais s'il date d'au plus 3 jours avant l'horloge locale
HORLOGE_TOLERANCE = timedelta(hours=24)
JOURS_BLOCAGE = 8            # jour 8 sans contact : blocage (spec § 3.6)
JOURS_AVERTISSEMENT = 6      # jours 6 et 7 : avertissement
FORMAT_BULLETIN = 1          # format connu ; un format plus grand est lu sur les listes connues (journalisé)
VERSION_ETAT = 1
BOM_UTF8 = b"\xef\xbb\xbf"

# États affichés (spec § 3.6)
AUCUNE = "AUCUNE"
CONNEXION_REQUISE = "CONNEXION_REQUISE"
BETA_TERMINEE = "BETA_TERMINEE"
MISE_A_JOUR_REQUISE = "MISE_A_JOUR_REQUISE"
BLOQUE_SANS_CONTACT = "BLOQUE_SANS_CONTACT"
AVERTISSEMENT = "AVERTISSEMENT"
NORMAL = "NORMAL"

_ALPHABET = re.compile(r"[A-Za-z0-9_-]+")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_VERSION = re.compile(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]{4}")
_HACHAGE = re.compile(r"[0-9a-f]{64}")
_ID_CLE = re.compile(r"[A-Z][0-9]{1,3}")


class JetonInvalide(ValueError):
    """Un jeton, un bulletin ou un état est refusé. Le message dit pourquoi (journal seulement, jamais affiché tel quel)."""


# ---------------------------------------------------------------- objets lus

@dataclass(frozen=True)
class Consigne:
    n: int
    emise: datetime
    fin_beta: date | None
    version_min: str | None
    adresses: tuple
    message: str | None
    cle: str
    jeton: str


@dataclass(frozen=True)
class Ticket:
    jour: date
    n: int
    h: str
    cle: str
    jeton: str


@dataclass(frozen=True)
class Releve:
    r: int
    emise: datetime
    cles: dict            # rôle -> {identifiant : 32 octets bruts}
    revoquees: frozenset
    n_min: int
    cle: str
    jeton: str


@dataclass(frozen=True)
class Trousseau:
    """Les clés que l'app accepte : par rôle, avec le numéro de génération. Les révoquées ne servent plus."""
    generation: int
    cles: dict            # rôle -> {identifiant : 32 octets bruts}
    revoquees: frozenset
    n_min: int

    def utilisables(self, role: str) -> dict:
        return {cle_id: brut for cle_id, brut in self.cles.get(role, {}).items() if cle_id not in self.revoquees}


@dataclass(frozen=True)
class Bulletin:
    releves: tuple        # jetons PLR1 (vides si la liste était trop longue ou mal formée)
    consignes: tuple      # jetons PLC1, dans l'ordre du bulletin (20 au plus)
    tickets: tuple        # jetons PLF1, 20 au plus
    journal: tuple        # ce qui a été ignoré en lisant le bulletin


@dataclass(frozen=True)
class Etat:
    """L'état local relu et revérifié (spec § 3.5), sans son `mac` (le mac est du lot B).

    `consigne_jeton` et `ticket_jeton` gardent le jeton stocké même quand il est oublié (clé révoquée) : la présence
    d'un ticket stocké fait la différence entre « premier » (jamais de contact) et « reprise » (contact perdu).
    `consigne` et `ticket` sont None quand le jeton n'est plus valide sous le trousseau courant."""
    trousseau: Trousseau
    releves: tuple        # jetons PLR1 acceptés dans la chaîne, dans l'ordre
    consigne_jeton: str | None
    consigne: Consigne | None
    ticket_jeton: str | None
    ticket: Ticket | None
    max_local: datetime | None


@dataclass(frozen=True)
class Resultat:
    etat: Etat            # état après le bulletin (à écrire seulement s'il a changé : voir meme_contenu)
    contact: bool         # contact réussi : consigne acceptée et ticket frais, non plus ancien que le ticket gardé
    jour_ticket: date | None   # jour du meilleur ticket lié (frais ou non), None s'il n'y en a pas
    journal: tuple


@dataclass(frozen=True)
class Affichage:
    etat: str
    raison: str | None    # premier | reprise | horloge | a_fini | verifier (selon l'état)
    jours_restants: int | None
    bloquant: bool
    message: str | None
    jour_contact: date | None


# ---------------------------------------------------------------- lecture stricte

def _refuser_constante(nom):
    raise JetonInvalide(f"JSON : constante interdite ({nom})")


def _objet_strict(paires):
    cles = [cle for cle, _ in paires]
    if len(set(cles)) != len(cles):
        raise JetonInvalide("JSON : clé dupliquée")
    return dict(paires)


def _charger_json(texte: str):
    try:
        return json.loads(texte, object_pairs_hook=_objet_strict, parse_constant=_refuser_constante)
    except JetonInvalide:
        raise
    except (ValueError, RecursionError) as erreur:
        raise JetonInvalide("JSON illisible") from erreur


def _b64enc(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def _b64dec(texte) -> bytes:
    """base64url sans remplissage, forme canonique seulement (un même octet ne s'écrit qu'une façon)."""
    if type(texte) is not str or not _ALPHABET.fullmatch(texte) or len(texte) % 4 == 1:
        raise JetonInvalide("base64url : caractères ou longueur incorrects")
    try:
        octets = base64.urlsafe_b64decode(texte + "=" * (-len(texte) % 4))
    except ValueError as erreur:
        raise JetonInvalide("base64url illisible") from erreur
    if _b64enc(octets) != texte:
        raise JetonInvalide("base64url non canonique")
    return octets


def _champ(charge: dict, nom: str):
    if nom not in charge:
        raise JetonInvalide(f"champ absent : {nom}")
    return charge[nom]


def _entier(valeur, minimum: int = 1) -> int:
    if type(valeur) is not int or not minimum <= valeur < BORNE_ENTIER:
        raise JetonInvalide("entier hors bornes ou pas un entier")
    return valeur


def _texte(valeur, maximum: int) -> str:
    if type(valeur) is not str or len(valeur) > maximum:
        raise JetonInvalide("texte absent, pas une chaîne, ou trop long")
    try:
        valeur.encode("utf-8")
    except UnicodeEncodeError as erreur:
        raise JetonInvalide("texte non UTF-8") from erreur
    return valeur


def _jour(valeur) -> date:
    if type(valeur) is not str or not _DATE.fullmatch(valeur):
        raise JetonInvalide("date : forme AAAA-MM-JJ attendue")
    try:
        return datetime.strptime(valeur, "%Y-%m-%d").date()
    except ValueError as erreur:
        raise JetonInvalide("date invalide") from erreur


def _instant(valeur) -> datetime:
    if type(valeur) is not str or not _INSTANT.fullmatch(valeur):
        raise JetonInvalide("heure : forme AAAA-MM-JJTHH:MM:SSZ attendue")
    try:
        return datetime.strptime(valeur, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as erreur:
        raise JetonInvalide("heure invalide") from erreur


def _version(valeur):
    """`AAAA.MM.JJ.HHMM` ou None (pas de version minimale)."""
    if valeur is None:
        return None
    if type(valeur) is not str or not _VERSION.fullmatch(valeur):
        raise JetonInvalide("version : forme AAAA.MM.JJ.HHMM attendue")
    try:
        date(int(valeur[0:4]), int(valeur[5:7]), int(valeur[8:10]))
    except ValueError as erreur:
        raise JetonInvalide("version : date invalide") from erreur
    if int(valeur[11:13]) > 23 or int(valeur[13:15]) > 59:
        raise JetonInvalide("version : heure invalide")
    return valeur


def _adresses(valeur) -> tuple:
    if type(valeur) is not list or not 1 <= len(valeur) <= ADRESSES_MAX:
        raise JetonInvalide("adresses : une à quatre attendues")
    for adresse in valeur:
        _texte(adresse, ADRESSE_MAX)
        if not adresse.startswith("https://"):
            raise JetonInvalide("adresse non https")
    return tuple(valeur)


def _identifiants(valeur) -> list:
    if type(valeur) is not list:
        raise JetonInvalide("liste d'identifiants attendue")
    for cle_id in valeur:
        if type(cle_id) is not str or not _ID_CLE.fullmatch(cle_id):
            raise JetonInvalide("identifiant de clé incorrect")
    return list(valeur)


def _cles_de_json(valeur) -> dict:
    """Un trousseau complet : exactement les trois rôles, chacun avec au moins une clé de 32 octets.

    Les identifiants sont UN SEUL espace pour les trois rôles : un même identifiant ne peut pas figurer deux fois."""
    if type(valeur) is not dict or set(valeur) != set(ROLES):
        raise JetonInvalide("cles : les trois rôles sont attendus")
    resultat = {}
    vus = set()
    for role in ROLES:
        groupe = valeur[role]
        if type(groupe) is not dict or not groupe:
            raise JetonInvalide(f"cles : rôle {role} vide ou mal formé")
        resultat[role] = {}
        for cle_id, texte in groupe.items():
            if not _ID_CLE.fullmatch(cle_id) or type(texte) is not str or len(texte) != 43:
                raise JetonInvalide("clé publique mal formée")
            if cle_id in vus:
                raise JetonInvalide(f"identifiant de clé utilisé deux fois : {cle_id}")
            vus.add(cle_id)
            brut = _b64dec(texte)
            if len(brut) != 32:
                raise JetonInvalide("clé publique : 32 octets attendus")
            resultat[role][cle_id] = brut
    return resultat


def _essayer(fonction, jeton, trousseau):
    """Relit un jeton gardé ; None s'il n'est plus valide sous ce trousseau (oubli, révocation, mauvaise signature)."""
    try:
        return fonction(jeton, trousseau)
    except JetonInvalide:
        return None


def _utc(instant: datetime) -> datetime:
    """Heure aware en UTC, à la seconde : le contenu écrit (`contenu_de_l_etat`) n'a que la seconde."""
    if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("heure sans fuseau : une heure aware est exigée")
    return instant.astimezone(timezone.utc).replace(microsecond=0)


def _debut_jour(jour: date) -> datetime:
    return datetime(jour.year, jour.month, jour.day, tzinfo=timezone.utc)


def _instant_texte(instant: datetime) -> str:
    return instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _max_jeton(*valeurs):
    """Le plus grand jeton présent (ordre lexicographique : commutatif, déterministe)."""
    return max((v for v in valeurs if v), default=None)


def empreinte(jeton: str) -> str:
    """SHA-256 hexadécimal du jeton PLC1 complet (le ticket s'y lie par `h`)."""
    return hashlib.sha256(jeton.encode("ascii")).hexdigest()


# ---------------------------------------------------------------- trousseau du code

def trousseau_du_code(modele=None) -> Trousseau:
    """Le trousseau compilé dans l'exe (`pla_commun/consigne_cles.py` par défaut)."""
    if modele is None:
        modele = consigne_cles
    return Trousseau(
        generation=_entier(modele.GENERATION, minimum=0),
        cles=_cles_de_json(modele.CLES),
        revoquees=frozenset(modele.REVOQUEES_CODE),
        n_min=_entier(modele.N_MIN_CODE, minimum=0),
    )


def _trousseau_apres(depart: Trousseau, releve: Releve) -> Trousseau:
    revoquees = depart.revoquees | releve.revoquees
    cles = {role: {cle_id: brut for cle_id, brut in groupe.items() if cle_id not in revoquees}
            for role, groupe in releve.cles.items()}
    return Trousseau(generation=releve.r, cles=cles, revoquees=revoquees, n_min=max(depart.n_min, releve.n_min))


# ---------------------------------------------------------------- jetons

def _decoder_jeton(jeton, prefixe: str, trousseau: Trousseau):
    """Vérifie le jeton (taille, morceaux, préfixe, alphabet, signature) AVANT de lire sa charge.

    Renvoie (charge, identifiant de la clé qui a signé). La signature n'est cherchée que parmi les clés utilisables du
    rôle du préfixe : une clé d'un autre rôle ne vérifie jamais. Les clés sont essayées une à une (la charge, qui dit
    quelle clé, ne se lit qu'après la signature) ; il y en a trois au plus par rôle."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if type(jeton) is not str:
        raise JetonInvalide("jeton : pas une chaîne")
    if len(jeton) > JETON_MAX:
        raise JetonInvalide("jeton trop long")
    morceaux = jeton.split(".")
    if len(morceaux) != 3:
        raise JetonInvalide("jeton : trois morceaux attendus")
    if morceaux[0] != prefixe:
        raise JetonInvalide("mauvais type de jeton")
    charge_b, signature_b = morceaux[1], morceaux[2]
    if not (_ALPHABET.fullmatch(charge_b) and _ALPHABET.fullmatch(signature_b)):
        raise JetonInvalide("caractères hors base64url")
    signature = _b64dec(signature_b)
    if len(signature) != 64:
        raise JetonInvalide("signature : 64 octets attendus")
    message = f"{prefixe}.{charge_b}".encode("ascii")
    role = ROLE_DU_PREFIXE[prefixe]
    cle_id = None
    for candidat, brut in sorted(trousseau.utilisables(role).items()):
        try:
            Ed25519PublicKey.from_public_bytes(brut).verify(signature, message)
        except InvalidSignature:
            continue
        cle_id = candidat
        break
    if cle_id is None:
        raise JetonInvalide(f"signature : aucune clé « {role} » utilisable ne la vérifie")
    try:
        texte = _b64dec(charge_b).decode("utf-8")
    except UnicodeDecodeError as erreur:
        raise JetonInvalide("charge : UTF-8 invalide") from erreur
    charge = _charger_json(texte)
    if type(charge) is not dict:
        raise JetonInvalide("charge : objet JSON attendu")
    return charge, cle_id


def _entete(charge: dict, cle_id: str) -> None:
    version = _champ(charge, "v")
    if type(version) is not int or version != VERSION_JETON:
        raise JetonInvalide("version de jeton non prise en charge")
    if _champ(charge, "produit") != PRODUIT:
        raise JetonInvalide("produit différent de « tracker »")
    if _champ(charge, "cle") != cle_id:
        raise JetonInvalide("clé du contenu différente de la clé de la signature")


def lire_consigne(jeton: str, trousseau: Trousseau) -> Consigne:
    charge, cle_id = _decoder_jeton(jeton, PREFIXE_CONSIGNE, trousseau)
    _entete(charge, cle_id)
    fin = _champ(charge, "fin_beta")
    return Consigne(
        n=_entier(_champ(charge, "n")),
        emise=_instant(_champ(charge, "emise")),
        fin_beta=None if fin is None else _jour(fin),
        version_min=_version(_champ(charge, "version_min")),
        adresses=_adresses(_champ(charge, "adresses")),
        message=None if _champ(charge, "message") is None else _texte(charge["message"], MESSAGE_MAX),
        cle=cle_id,
        jeton=jeton,
    )


def lire_ticket(jeton: str, trousseau: Trousseau) -> Ticket:
    charge, cle_id = _decoder_jeton(jeton, PREFIXE_TICKET, trousseau)
    _entete(charge, cle_id)
    h = _champ(charge, "h")
    if type(h) is not str or not _HACHAGE.fullmatch(h):
        raise JetonInvalide("h : empreinte SHA-256 hexadécimale attendue")
    return Ticket(jour=_jour(_champ(charge, "jour")), n=_entier(_champ(charge, "n")), h=h, cle=cle_id, jeton=jeton)


def lire_releve(jeton: str, trousseau: Trousseau) -> Releve:
    charge, cle_id = _decoder_jeton(jeton, PREFIXE_RELEVE, trousseau)
    _entete(charge, cle_id)
    return Releve(
        r=_entier(_champ(charge, "r")),
        emise=_instant(_champ(charge, "emise")),
        cles=_cles_de_json(_champ(charge, "cles")),
        revoquees=frozenset(_identifiants(_champ(charge, "revoquees"))),
        n_min=_entier(_champ(charge, "n_min"), minimum=0),
        cle=cle_id,
        jeton=jeton,
    )


def signer(prefixe: str, charge: dict, cle_privee) -> str:
    """Émet un jeton signé. Réservé aux outils (`tools/consigne.py`, la tâche du miroir) : `cle_privee` est une clé
    Ed25519 de `cryptography` ; le module ne la lit pas et ne la garde pas."""
    if prefixe not in ROLE_DU_PREFIXE:
        raise ValueError(f"préfixe inconnu : {prefixe}")
    corps = json.dumps(charge, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    partie = f"{prefixe}.{_b64enc(corps)}"
    jeton = f"{partie}.{_b64enc(cle_privee.sign(partie.encode('ascii')))}"
    if len(jeton) > JETON_MAX:
        raise ValueError("jeton trop long (plus de 2 048 caractères)")
    return jeton


def octets_bulletin(donnees: dict) -> bytes:
    """Le bulletin tel qu'il est servi : JSON canonique, 16 384 octets au plus."""
    octets = json.dumps(donnees, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(octets) > BULLETIN_MAX:
        raise ValueError("bulletin trop gros (plus de 16 384 octets)")
    return octets


def lire_bulletin(octets) -> Bulletin:
    """Lit un bulletin brut (octets ou texte). Tout est borné avant décodage (spec § 3.2).

    Un BOM UTF-8 est refusé ici ; le lot B le retire avant l'appel. Un `format` entier ≥ 1 est accepté : au-delà de 1,
    les trois listes connues sont lues si leur forme est bonne, et l'écart est journalisé (spec § 3.2)."""
    if isinstance(octets, str):
        try:
            octets = octets.encode("utf-8")
        except UnicodeEncodeError as erreur:
            raise JetonInvalide("bulletin : texte non UTF-8") from erreur
    if type(octets) not in (bytes, bytearray) or not 0 < len(octets) <= BULLETIN_MAX:
        raise JetonInvalide("bulletin vide, trop gros ou pas des octets")
    if bytes(octets).startswith(BOM_UTF8):
        raise JetonInvalide("bulletin : BOM UTF-8 présent (le lot B le retire avant la lecture)")
    try:
        texte = bytes(octets).decode("utf-8")
    except UnicodeDecodeError as erreur:
        raise JetonInvalide("bulletin : UTF-8 invalide") from erreur
    donnees = _charger_json(texte)
    if type(donnees) is not dict:
        raise JetonInvalide("bulletin : objet JSON attendu")
    format_lu = donnees.get("format")
    if type(format_lu) is not int or format_lu < 1:
        raise JetonInvalide("bulletin : format absent ou invalide")

    journal = []
    if format_lu != FORMAT_BULLETIN:
        journal.append(f"format {format_lu} : seuls les champs connus sont lus")
    releves = []
    brut = donnees.get("releves")
    if brut is not None:
        if type(brut) is list and len(brut) <= RELEVES_MAX and all(type(x) is str for x in brut):
            releves = list(brut)
        else:
            journal.append("liste de relèves ignorée (plus de 4, ou mal formée)")
    consignes = []
    brut = donnees.get("consignes")
    if brut is not None:
        if type(brut) is list:
            consignes = [x for x in brut if type(x) is str]
            if len(consignes) > CONSIGNES_LUES_MAX:
                journal.append(f"consignes : seules les {CONSIGNES_LUES_MAX} premières sont lues")
                consignes = consignes[:CONSIGNES_LUES_MAX]
        else:
            journal.append("liste de consignes ignorée (mal formée)")
    tickets = []
    brut = donnees.get("tickets")
    if brut is not None:
        if type(brut) is list:
            tickets = [x for x in brut if type(x) is str]
            if len(tickets) > TICKETS_LUS_MAX:
                journal.append(f"tickets : seuls les {TICKETS_LUS_MAX} premiers sont lus")
                tickets = tickets[:TICKETS_LUS_MAX]
        else:
            journal.append("liste de tickets ignorée (mal formée)")
    return Bulletin(tuple(releves), tuple(consignes), tuple(tickets), tuple(journal))


# ---------------------------------------------------------------- relèves et chaîne

def appliquer_releves(trousseau: Trousseau, nb_deja: int, jetons) -> tuple:
    """Applique les relèves dans l'ordre (spec § 3.3, étape 1), avec la règle B1 (2026-11-11).

    `nb_deja` = nombre de relèves déjà gardées dans la chaîne (pour la limite de 8). Une relève qui ne se vérifie pas
    avec le trousseau courant (signée par une clé remplacée ou révoquée, par exemple une relève déjà appliquée), ou dont
    le numéro ne suit pas, est IGNORÉE et journalisée ; on continue. Une relève de numéro ≤ génération courante est
    écartée sans effet. La 9e relève gardée arrête la lecture. Sécurité : une relève n'est appliquée que si elle se
    vérifie avec une clé de secours utilisable du trousseau courant et si son numéro vaut génération + 1.
    Renvoie (trousseau final, jetons acceptés dans cet appel, journal)."""
    journal = []
    acceptees = []
    courant = trousseau
    for jeton in jetons:
        try:
            releve = lire_releve(jeton, courant)
        except JetonInvalide as erreur:
            journal.append(f"relève ignorée (non vérifiable avec le trousseau courant) : {erreur}")
            continue
        if releve.r <= courant.generation:
            journal.append(f"relève {releve.r} déjà connue (écartée)")
            continue
        if releve.r != courant.generation + 1:
            journal.append(f"relève {releve.r} ne suit pas la génération {courant.generation} (ignorée)")
            continue
        if nb_deja + len(acceptees) >= RELEVES_GARDEES_MAX:
            journal.append("9e relève refusée : l'état garde déjà 8 relèves")
            break
        courant = _trousseau_apres(courant, releve)
        acceptees.append(jeton)
    return courant, tuple(acceptees), tuple(journal)


# ---------------------------------------------------------------- état local (contenu, sans mac)

def _plancher(max_local, ticket):
    """L'heure locale vue n'est jamais avant le début du jour du dernier contact (spec § 3.4, imposé à la lecture)."""
    if ticket is None:
        return max_local
    debut = _debut_jour(ticket.jour)
    if max_local is None or max_local < debut:
        return debut
    return max_local


def _consigne_gardee(jeton, trousseau: Trousseau):
    """La consigne gardée, si elle se vérifie sous ce trousseau et si son n° n'est pas sous le plancher du trousseau."""
    if not jeton:
        return None
    consigne = _essayer(lire_consigne, jeton, trousseau)
    if consigne is not None and consigne.n < trousseau.n_min:
        return None
    return consigne


def _etat(trousseau, releves, consigne_jeton, ticket_jeton, max_local) -> Etat:
    """L'état tel qu'il se relit. TOUT état (relu ou calculé en mémoire) passe par cette fonction (I2)."""
    consigne = _consigne_gardee(consigne_jeton, trousseau)
    ticket = _essayer(lire_ticket, ticket_jeton, trousseau) if ticket_jeton else None
    if ticket is not None and (consigne is None or ticket.n > consigne.n):
        ticket = None
    return Etat(trousseau=trousseau, releves=tuple(releves), consigne_jeton=consigne_jeton or None,
                consigne=consigne, ticket_jeton=ticket_jeton or None, ticket=ticket,
                max_local=_plancher(max_local, ticket))


def _etat_vide(trousseau: Trousseau) -> Etat:
    return Etat(trousseau, (), None, None, None, None, None)


def lire_etat(contenu, *, scellement_verifie: bool, trousseau_code: Trousseau | None = None) -> Etat | None:
    """Relit le contenu de l'état (dict, SANS `mac`) et revérifie chaque jeton. None si le contenu est illisible.

    `scellement_verifie` doit valoir True : l'appelant a déjà vérifié le scellement (`mac`, lot B) AVANT cet appel.
    Cette fonction ne voit pas le `mac` et ne vérifie rien de ce côté."""
    if scellement_verifie is not True:
        raise ValueError("lire_etat : le scellement doit être vérifié avant l'appel (scellement_verifie=True)")
    if type(contenu) is not dict or type(contenu.get("v")) is not int or contenu.get("v") != VERSION_ETAT:
        return None
    releves = contenu.get("releves")
    if type(releves) is not list or not all(type(x) is str for x in releves):
        return None
    consigne_jeton = contenu.get("consigne")
    ticket_jeton = contenu.get("ticket")
    if not (consigne_jeton is None or type(consigne_jeton) is str) or not (ticket_jeton is None or type(ticket_jeton) is str):
        return None
    try:
        max_local = None if contenu.get("max_local") is None else _instant(contenu["max_local"])
    except JetonInvalide:
        return None
    trousseau = trousseau_code if trousseau_code is not None else trousseau_du_code()
    chaine, acceptees, _ = appliquer_releves(trousseau, 0, releves)
    return _etat(chaine, acceptees, consigne_jeton, ticket_jeton, max_local)


def contenu_de_l_etat(etat: Etat) -> dict:
    """Le contenu à écrire (le `mac` s'ajoute au lot B)."""
    return {
        "v": VERSION_ETAT,
        "releves": list(etat.releves),
        "consigne": etat.consigne_jeton,
        "ticket": etat.ticket_jeton,
        "max_local": None if etat.max_local is None else _instant_texte(etat.max_local),
    }


def meme_contenu(a: Etat | None, b: Etat | None) -> bool:
    """Deux états s'écrivent-ils pareil ? (le lot B n'écrit que si le contenu change)."""
    ca = None if a is None else contenu_de_l_etat(a)
    cb = None if b is None else contenu_de_l_etat(b)
    return ca == cb


def mettre_a_jour_horloge(etat: Etat, maintenant: datetime) -> Etat:
    """Écriture horaire de `max_local` (spec § 3.4) : la plus grande heure vue, plancher respecté. Pure.

    C'est le SEUL événement qui fait monter `max_local` hors d'un bulletin ; seul un contact (`evaluer_bulletin`) peut le
    faire descendre."""
    maintenant = _utc(maintenant)
    nouveau = maintenant if etat.max_local is None else max(etat.max_local, maintenant)
    return dataclasses.replace(etat, max_local=_plancher(nouveau, etat.ticket))


def fusionner(a: Etat | None, b: Etat | None) -> Etat | None:
    """Fusion de DEUX MAGASINS FRÈRES (spec § 3.5). Pure et commutative : fusionner(a, b) == fusionner(b, a).

    ATTENTION : ne jamais fusionner un état avec une copie plus ancienne de lui-même. `max_local` est pris au plus grand,
    donc une fusion avec un ancêtre effacerait l'abaissement fait par un contact. Pour le lot B : fusionner disque et
    registre entre eux, puis REJOUER l'événement en mémoire sur le résultat (`evaluer_bulletin`, `mettre_a_jour_horloge`).

    Champs : chaîne de relèves la plus longue (génération la plus haute, puis le plus grand tuple de jetons) ; consigne
    acceptée au plus grand `n` (égalité : le plus grand jeton) ; ticket le plus récent (égalité : le plus grand jeton),
    signature valide, `n` ≤ celui de la consigne retenue ; `max_local` le plus grand. Un état absent ne compte pas."""
    if a is None:
        return b
    if b is None:
        return a
    gagnant = max((a, b), key=lambda e: (e.trousseau.generation, e.releves))
    t = gagnant.trousseau
    consignes = [c for c in (_consigne_gardee(x, t) for x in (a.consigne_jeton, b.consigne_jeton) if x) if c is not None]
    consigne = max(consignes, key=lambda c: (c.n, c.jeton), default=None)
    consigne_jeton = consigne.jeton if consigne is not None else _max_jeton(a.consigne_jeton, b.consigne_jeton)
    tickets = []
    if consigne is not None:
        for jeton in (a.ticket_jeton, b.ticket_jeton):
            ticket = _essayer(lire_ticket, jeton, t) if jeton else None
            if ticket is not None and ticket.n <= consigne.n:
                tickets.append(ticket)
    ticket = max(tickets, key=lambda k: (k.jour, k.jeton), default=None)
    ticket_jeton = ticket.jeton if ticket is not None else _max_jeton(a.ticket_jeton, b.ticket_jeton)
    maxes = [x for x in (a.max_local, b.max_local) if x is not None]
    return _etat(t, gagnant.releves, consigne_jeton, ticket_jeton, max(maxes, default=None))


# ---------------------------------------------------------------- bulletin : règles d'acceptation (spec § 3.3)

def evaluer_bulletin(etat: Etat | None, bulletin: Bulletin, maintenant: datetime, *, jour_site: date | None = None,
                     trousseau_code: Trousseau | None = None) -> Resultat:
    """Applique le bulletin à l'état (ordre du § 3.3 : relèves, consigne, ticket) et renvoie le nouvel état.

    `maintenant` : heure aware de l'horloge locale. `jour_site` : `datetime.date` UTC de l'en-tête `Date` de la réponse,
    ou None (absent ou illisible) ; le plafond est P = min(jour_local, jour_site).
    `trousseau_code` ne sert que si `etat` est None : un état fourni porte déjà son trousseau.
    Le contact (I1) : un ticket frais, lié à la consigne gardée, et NON PLUS ANCIEN que le ticket gardé."""
    if jour_site is not None and type(jour_site) is not date:
        raise TypeError("jour_site : une datetime.date (jour UTC) ou None")
    maintenant = _utc(maintenant)
    jour_local = maintenant.date()
    base = etat if etat is not None else _etat_vide(trousseau_code if trousseau_code is not None else trousseau_du_code())
    journal = list(bulletin.journal)

    # 1. relèves (règle B1 : une relève non vérifiable ou non consécutive est ignorée, on continue)
    t, nouvelles, journal_releves = appliquer_releves(base.trousseau, len(base.releves), bulletin.releves)
    journal.extend(journal_releves)
    releves = tuple(base.releves) + nouvelles
    consigne = _consigne_gardee(base.consigne_jeton, t)
    consigne_jeton = base.consigne_jeton

    # 2. consigne : la consigne acceptable au plus grand n, quel que soit son rang dans le bulletin
    plancher = max(t.n_min, consigne.n if consigne is not None else 0)
    candidates = []
    for jeton in bulletin.consignes:
        try:
            candidate = lire_consigne(jeton, t)
        except JetonInvalide as erreur:
            journal.append(f"consigne ignorée : {erreur}")
            continue
        if candidate.n < plancher:
            journal.append(f"consigne n° {candidate.n} sous le plancher ou sous la consigne gardée (refusée)")
            continue
        if consigne is not None and candidate.n == consigne.n:
            if candidate.jeton != consigne.jeton:
                journal.append(f"conflit : deux consignes différentes portent le n° {candidate.n} (la gardée reste)")
            continue                                  # identique : rien ne change ; différente : conflit
        if consigne is not None and candidate.emise < consigne.emise:
            journal.append(f"consigne n° {candidate.n} émise avant la consigne gardée (refusée)")
            continue
        candidates.append(candidate)
    if candidates:
        choisie = max(candidates, key=lambda c: (c.n, c.jeton))
        consigne_jeton = choisie.jeton
        consigne = _consigne_gardee(consigne_jeton, t)

    # 3. ticket frais, lié à la consigne gardée, plafonné par le jour du site, et pas plus ancien que le ticket gardé
    ticket_jeton = base.ticket_jeton
    ticket = _essayer(lire_ticket, ticket_jeton, t) if ticket_jeton else None
    contact = False
    jour_ticket = None
    meilleur = None
    if consigne is not None:
        plafond = jour_local if jour_site is None else min(jour_local, jour_site)
        lien = empreinte(consigne.jeton)
        for jeton in bulletin.tickets:
            try:
                candidat = lire_ticket(jeton, t)
            except JetonInvalide as erreur:
                journal.append(f"ticket ignoré : {erreur}")
                continue
            if candidat.n != consigne.n or candidat.h != lien or candidat.jour > plafond:
                continue
            if meilleur is None or (candidat.jour, candidat.jeton) > (meilleur.jour, meilleur.jeton):
                meilleur = candidat
    if meilleur is not None:
        jour_ticket = meilleur.jour
        frais = meilleur.jour >= jour_local - timedelta(days=JOURS_FRAIS)
        plus_recent = ticket is None or meilleur.jour >= ticket.jour
        if not plus_recent:
            journal.append("ticket plus ancien que le ticket gardé : pas un contact (I1)")
        contact = frais and plus_recent
        if contact:
            ticket, ticket_jeton = meilleur, meilleur.jeton

    # 4. heure locale : un contact la ramène au début du jour du ticket (seul cas où elle descend)
    if contact:
        max_local = max(maintenant, _debut_jour(meilleur.jour))
    elif base.max_local is not None:
        max_local = max(maintenant, base.max_local)
    else:
        max_local = maintenant

    # 5. l'état en mémoire est construit par la MÊME fonction que la relecture (I2)
    nouvel = _etat(t, releves, consigne_jeton, ticket_jeton, max_local)
    return Resultat(etat=nouvel, contact=contact, jour_ticket=jour_ticket, journal=tuple(journal))


# ---------------------------------------------------------------- machine à états (spec § 3.6)

def _version_trop_ancienne(version_exe, version_min: str) -> bool:
    """Un exe sans version valide est traité comme inférieur à toute version minimale."""
    if version_exe is None:
        return True
    try:
        _version(version_exe)
    except JetonInvalide:
        return True
    return version_exe < version_min


def etat_affiche(etat: Etat | None, maintenant: datetime, *, version_exe, client: bool, beta: bool,
                 contact_ce_lancement: bool) -> Affichage:
    """Ce qu'il faut afficher, dans l'ordre de priorité du § 3.6. Fonction pure.

    `client` : édition client (False = développement, rien ne se passe). `beta` : exe de la bêta (la date de fin
    s'applique). `version_exe` : `AAAA.MM.JJ.HHMM` ou None. `contact_ce_lancement` : un contact réussi depuis le
    lancement en cours (la règle d'horloge ne bloque pas après un contact).
    Priorité : premier, reprise, BÊTA TERMINÉE, MISE À JOUR REQUISE, horloge, compteur."""
    maintenant = _utc(maintenant)
    if not client:
        return Affichage(AUCUNE, None, None, False, None, None)
    message = etat.consigne.message if etat is not None and etat.consigne is not None else None
    if etat is None or etat.ticket_jeton is None:
        return Affichage(CONNEXION_REQUISE, "premier", None, True, message, None)
    if etat.consigne is None or etat.ticket is None:
        return Affichage(CONNEXION_REQUISE, "reprise", None, True, message, None)
    consigne = etat.consigne
    jour_contact = etat.ticket.jour
    heure_ref = maintenant if etat.max_local is None else max(maintenant, etat.max_local)
    jour_ref = heure_ref.date()
    if beta and consigne.fin_beta is not None and jour_ref >= consigne.fin_beta:
        raison = "a_fini" if jour_contact >= consigne.fin_beta else "verifier"
        return Affichage(BETA_TERMINEE, raison, None, True, message, jour_contact)
    if consigne.version_min is not None and _version_trop_ancienne(version_exe, consigne.version_min):
        return Affichage(MISE_A_JOUR_REQUISE, None, None, True, message, jour_contact)
    if etat.max_local is not None and maintenant < etat.max_local - HORLOGE_TOLERANCE and not contact_ce_lancement:
        return Affichage(CONNEXION_REQUISE, "horloge", None, True, message, jour_contact)
    k = (jour_ref - jour_contact).days
    if k >= JOURS_BLOCAGE:
        return Affichage(BLOQUE_SANS_CONTACT, None, None, True, message, jour_contact)
    if k >= JOURS_AVERTISSEMENT:
        return Affichage(AVERTISSEMENT, None, JOURS_BLOCAGE - k, False, message, jour_contact)
    return Affichage(NORMAL, None, None, False, message, jour_contact)
