#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyseur de reseau local : appareils connectes (IP, MAC, nom) + test de vitesse Internet."""

import argparse
import http.client
import ipaddress
import json
import platform
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

SYS = platform.system()
URL_TEST = "https://speed.hetzner.de/100MB.bin"
IPS_RECOURS = ["104.16.124.96", "104.16.111.35", "172.64.4.30", "162.159.133.2"]

VENDORS = {
    "00:11:32": "Apple",
    "24:4B:FE": "Apple",
    "AC:BC:32": "Apple",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:15:5D": "Hyper-V",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "3C:5A:B4": "Raspberry Pi",
    "00:16:3E": "Xen",
    "EC:FA:BC": "Sagemcom",
    "F0:9F:C2": "Sagemcom",
    "BC:AD:28": "Ubiquiti",
    "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "50:C7:BF": "TP-Link / Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "00:1B:44": "Tenda",
    "D8:07:B6": "TP-Link",
    "3C:84:6A": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "74:DA:38": "TP-Link",
    "E8:DE:27": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "C0:3F:0E": "TP-Link",
    "00:14:BF": "Linksys",
    "E0:63:DA": "Asus",
    "44:6D:57": "Asus",
    "3C:7D:0A": "Netgear",
    "A0:40:A0": "Netgear",
    "00:1B:2F": "Intel",
    "3C:FD:FE": "Intel",
    "D8:BB:C1": "Intel",
    "00:1C:AB": "Dell",
    "00:21:5A": "Dell",
    "6C:3B:E5": "Dell",
    "54:34:D0": "Samsung",
    "8C:77:12": "Samsung",
    "A8:0C:63": "Samsung",
    "24:26:2C": "Realtek",
    "3C:52:82": "Realtek",
    "52:54:00": "QEMU",
    "00:05:69": "Proxmox",
    "BC:24:11": "Proxmox",
    "C8:3A:35": "Google Nest",
    "18:B4:30": "Google",
    "F4:F5:D8": "Google",
    "00:1A:11": "Google",
    "3C:5A:37": "Huawei",
    "F8:04:2E": "Huawei",
    "9C:D9:23": "Huawei",
    "04:8D:38": "Xiaomi",
    "6C:7E:5E": "Xiaomi",
    "78:11:DC": "Xiaomi",
    "00:0D:30": "Nokia",
    "04:92:26": "Amazon",
    "AC:63:BE": "Amazon",
    "1C:56:FE": "Amazon",
    "60:71:22": "Sony",
    "F8:A2:D6": "Sony",
    "DC:0B:1A": "Sony",
    "A0:BD:1D": "Sony",
    "00:0F:A6": "Espressif (ESP32)",
    "24:0A:C4": "Espressif (ESP8266)",
    "C0:EE:FB": "Espressif",
    "00:17:88": "Philips Hue",
    "D0:52:A8": "Ring",
    "40:8D:5C": "Wyze",
    "F8:8F:CA": "JBL",
    "68:86:E7": "JBL",
    "50:3E:AA": "Sonos",
    "94:9F:3E": "TP-Link Kasa",
}


def executer(commande, timeout=8):
    try:
        resultat = subprocess.run(commande, capture_output=True, text=True, timeout=timeout)
        return resultat.stdout + resultat.stderr
    except Exception:
        return ""


def obtenir_ip_locale():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        pass
    finally:
        s.close()
    try:
        return socket.gethostbyname_ex(socket.gethostname())[2][0]
    except OSError:
        return "127.0.0.1"


def obtenir_passarelle():
    if SYS == "Windows":
        sortie = executer(["route", "print", "-4"], timeout=10)
        for ligne in sortie.splitlines():
            if re.match(r"^\s*0\.0\.0\.0\s", ligne):
                champs = ligne.split()
                if len(champs) >= 3:
                    return champs[2]
    else:
        sortie = executer(["ip", "route", "show", "default"], timeout=5)
        m = re.search(r"via ([\d.]+)", sortie)
        if m:
            return m.group(1)
    return None


def ping(ip, delai=1):
    if SYS == "Windows":
        commande = ["ping", "-n", "1", "-w", str(int(delai * 1000)), ip]
    else:
        commande = ["ping", "-c", "1", "-W", str(int(delai)), ip]
    return executer(commande, timeout=delai + 4) != ""


def lire_table_arp():
    if SYS == "Windows":
        sortie = executer(["arp", "-a"], timeout=10)
    else:
        sortie = executer(["arp", "-an"], timeout=10)
    table = {}
    pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")
    for m in pattern.finditer(sortie):
        ip = m.group(1)
        mac = m.group(2).replace("-", ":").lower()
        table[ip] = mac
    return table


def nom_par_dns(ip):
    try:
        nom = socket.gethostbyaddr(ip)[0]
        if nom:
            return nom.rstrip(".")
    except Exception:
        pass
    return ""


def encoder_nbns(nom):
    nom = (nom.upper() + " " * 15)[:15] + "\x00"
    enc = ""
    for c in nom:
        enc += chr(ord(c) // 16 + 0x41) + chr(ord(c) % 16 + 0x41)
    return enc.encode("ascii")


def decoder_nbns(data):
    if len(data) < 48:
        return ""
    nom = ""
    champ = data[15:47]
    for i in range(0, 32, 2):
        v = (champ[i] - 0x41) * 16 + (champ[i + 1] - 0x41)
        if v == 0:
            break
        if v > 0xFF or not (32 <= v <= 126):
            continue
        nom += chr(v)
    return nom.strip()


def nom_par_nbtstat(ip):
    if SYS != "Windows":
        return ""
    sortie = executer(["nbtstat", "-A", ip], timeout=6)
    for ligne in sortie.splitlines():
        m = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", ligne)
        if m:
            return m.group(1)
    return ""


def noms_par_nbns(ips, delai=3):
    noms = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attentes = {}
    for ip in ips:
        tid = random.randrange(1, 65536)
        paquet = struct.pack(">HHHHHH", tid, 0x0110, 1, 0, 0, 0)
        paquet += b"\x20" + encoder_nbns("*") + struct.pack(">HH", 0x0021, 0x0001)
        try:
            s.sendto(paquet, (ip, 137))
            attentes[tid] = ip
        except OSError:
            pass
    if attentes:
        fin = time.time() + delai
        while time.time() < fin:
            s.settimeout(max(0.1, fin - time.time()))
            try:
                data, _ = s.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            if len(data) < 48:
                continue
            tid = struct.unpack(">H", data[:2])[0]
            ip = attentes.get(tid)
            if ip:
                nom = decoder_nbns(data)
                if nom and nom != "*":
                    noms[ip] = nom
    s.close()
    return noms


def lire_nom(data, offset):
    labels = []
    vu = set()
    fin = offset
    while offset < len(data) and offset not in vu:
        vu.add(offset)
        t = data[offset]
        if t == 0:
            if fin == offset:
                fin = offset + 1
            break
        if t & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointeur = ((t & 0x3F) << 8) | data[offset + 1]
            if fin == offset:
                fin = offset + 2
            if pointeur >= len(data):
                break
            offset = pointeur
            continue
        offset += 1
        if offset + t > len(data):
            break
        labels.append(data[offset:offset + t].decode("ascii", "ignore"))
        offset += t
    return ".".join(labels), fin


def sauter_labels(data, offset):
    while offset < len(data):
        t = data[offset]
        if t == 0:
            return offset + 1
        if t & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + t
    return offset


def analyser_reponses(donnees):
    resultats = []
    if len(donnees) < 12:
        return resultats
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", donnees[:12])
    offset = 12
    for _ in range(qd):
        offset = sauter_labels(donnees, offset)
        offset += 4
    for _ in range(an):
        if offset >= len(donnees):
            break
        nom_rec = lire_nom(donnees, offset)[0]
        offset = sauter_labels(donnees, offset)
        if offset + 10 > len(donnees):
            break
        type_, _, _, rdlen = struct.unpack(">HHIH", donnees[offset:offset + 10])
        offset += 10
        if type_ == 12:
            cible, _ = lire_nom(donnees, offset)
            resultats.append((nom_rec.lower().rstrip("."), cible.rstrip(".")))
        offset += rdlen
    return resultats


def noms_par_mdns(ips, ip_locale, delai=3):
    noms = {}
    if not ips:
        return noms
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("", 5353))
    except OSError:
        try:
            s.bind(("", 0))
        except OSError:
            s.close()
            return noms
    if ip_locale:
        try:
            membre = struct.pack("4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton(ip_locale))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membre)
        except OSError:
            pass
    for ip in ips:
        nom_rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        paquet = struct.pack(">HHHHHH", random.randrange(1, 65536), 0x0000, 1, 0, 0, 0)
        for partie in nom_rev.split("."):
            paquet += bytes([len(partie)]) + partie.encode()
        paquet += b"\x00" + struct.pack(">HH", 12, 1)
        try:
            s.sendto(paquet, ("224.0.0.251", 5353))
        except OSError:
            pass
    fin = time.time() + delai
    while time.time() < fin:
        s.settimeout(max(0.1, fin - time.time()))
        try:
            data, _ = s.recvfrom(4096)
        except (socket.timeout, OSError):
            break
        for nom_rec, cible in analyser_reponses(data):
            champs = nom_rec.split(".")
            if len(champs) >= 5 and champs[-2] == "in-addr":
                ip = ".".join(reversed(champs[0:4]))
                if ip in ips and cible:
                    noms[ip] = cible
    s.close()
    return noms


def nom_par_ptr(ip, serveurs, delai=2):
    nom_rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    for serv in serveurs:
        if not serv:
            continue
        paquet = struct.pack(">HHHHHH", random.randrange(1, 65536), 0x0100, 1, 0, 0, 0)
        for partie in nom_rev.split("."):
            paquet += bytes([len(partie)]) + partie.encode()
        paquet += b"\x00" + struct.pack(">HH", 12, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(delai)
        try:
            s.sendto(paquet, (serv, 53))
            data, _ = s.recvfrom(4096)
            s.close()
            for _, cible in analyser_reponses(data):
                if cible:
                    return cible
        except (OSError, socket.timeout):
            s.close()
            continue
    return None


def nom_par_ptr_doh(ip, delai=4):
    nom_rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    for serveur, sni in (("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google")):
        try:
            contexte = ssl.create_default_context()
            sock = socket.create_connection((serveur, 443), timeout=8)
            s = contexte.wrap_socket(sock, server_hostname=sni)
            requete = f"GET /dns-query?name={nom_rev}&type=PTR HTTP/1.1\r\nHost: {sni}\r\nAccept: application/dns-json\r\nUser-Agent: python\r\nConnection: close\r\n\r\n"
            s.sendall(requete.encode())
            reponse = b""
            while True:
                morceau = s.recv(65536)
                if not morceau:
                    break
                reponse += morceau
            s.close()
            donnees = json.loads(reponse.split(b"\r\n\r\n", 1)[1])
            for a in donnees.get("Answer", []):
                if a.get("type") == 12:
                    return a["data"].rstrip(".")
        except Exception:
            continue
    return None


def constructeur(mac):
    return VENDORS.get(mac[:8].upper(), "Inconnu")


def mac_locale():
    brut = "%012x" % uuid.getnode()
    return ":".join(brut[i:i + 2] for i in range(0, 12, 2))


def trouver_appareils(ip_locale, delai=1.0):
    reseau = ".".join(ip_locale.split(".")[:3]) + ".0/24"
    hotes = [str(h) for h in ipaddress.ip_network(reseau, strict=False).hosts()]
    print(f"[*] Recherche d'appareils sur {reseau} ({len(hotes)} adresses testees)...")
    with ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(ping, hotes, [delai] * len(hotes)))
    table_arp = lire_table_arp()
    appareils = []
    for ip, mac in sorted(table_arp.items(), key=lambda x: [int(p) for p in x[0].split(".")]):
        if ip == ip_locale:
            continue
        if mac.startswith(("ff:", "01:00:5e")) or mac == "00:00:00:00:00:00":
            continue
        if ip.startswith(("224.", "239.", "255.")):
            continue
        appareils.append({"ip": ip, "mac": mac})
    passerelle = obtenir_passarelle()
    print("[*] Identification des noms (DNS, NetBIOS, mDNS)...")
    with ThreadPoolExecutor(max_workers=32) as pool:
        noms_initiaux = list(pool.map(nom_par_dns, [a["ip"] for a in appareils]))
    for a, n in zip(appareils, noms_initiaux):
        a["nom"] = n
        a["propriete"] = ""
    restants = [a for a in appareils if not a["nom"]]
    if restants:
        print("[*] Requetes NetBIOS (port 137)...")
        noms_nb = noms_par_nbns([a["ip"] for a in restants])
        for a in restants:
            nb = noms_nb.get(a["ip"])
            if nb:
                a["nom"] = nb
        restants = [a for a in restants if not a["nom"]]
    if restants:
        print("[*] Requetes mDNS (multicast 224.0.0.251:5353)...")
        noms_md = noms_par_mdns([a["ip"] for a in restants], ip_locale)
        for a in restants:
            md = noms_md.get(a["ip"])
            if md:
                a["nom"] = md
        restants = [a for a in restants if not a["nom"]]
    if restants:
        print("[*] Requetes DNS inverses (PTR) supplementaires...")
        serveurs = list(dict.fromkeys([passerelle, "8.8.8.8", "1.1.1.1"]))

        def ptr(a):
            return nom_par_ptr(a["ip"], serveurs) or nom_par_ptr_doh(a["ip"])

        with ThreadPoolExecutor(max_workers=8) as pool:
            noms_ptr = list(pool.map(ptr, restants))
        for a, n in zip(restants, noms_ptr):
            if n:
                a["nom"] = n
        restants = [a for a in restants if not a["nom"]]
    if restants and SYS == "Windows":
        print("[*] Requetes nbtstat en parallele...")
        with ThreadPoolExecutor(max_workers=8) as pool:
            noms_nb2 = list(pool.map(nom_par_nbtstat, [a["ip"] for a in restants]))
        for a, n in zip(restants, noms_nb2):
            if n:
                a["nom"] = n
    appareils.append({"ip": ip_locale, "mac": mac_locale(), "nom": socket.gethostname(), "propriete": "moi"})
    appareils.sort(key=lambda a: [int(p) for p in a["ip"].split(".")])
    return appareils


def latence_moyenne(ip, nombre=5):
    valeurs = []
    for _ in range(nombre):
        if SYS == "Windows":
            commande = ["ping", "-n", "1", "-w", "2000", ip]
        else:
            commande = ["ping", "-c", "1", "-W", "2", ip]
        debut = time.perf_counter()
        sortie = executer(commande, timeout=4)
        m = re.search(r"(?:temps|time)[=<>]*\s*(\d+)\s*ms", sortie, re.IGNORECASE)
        if m:
            valeurs.append(float(m.group(1)))
        elif sortie:
            valeurs.append((time.perf_counter() - debut) * 1000)
    return (sum(valeurs) / len(valeurs)) if valeurs else None


def telecharger_mesure(hote, chemin, duree, ip=None, port=443, tls=True):
    octets = 0
    debut = time.time()
    if tls:
        if ip is None:
            client = http.client.HTTPSConnection(hote, port, timeout=15)
        else:
            contexte = ssl.create_default_context()
            sock = socket.create_connection((ip, port), timeout=15)
            client = http.client.HTTPSConnection(hote, port, timeout=15)
            client.sock = contexte.wrap_socket(sock, server_hostname=hote)
    else:
        client = http.client.HTTPConnection(ip or hote, port, timeout=15)
    try:
        client.putrequest("GET", chemin)
        client.putheader("Host", hote)
        client.putheader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        client.putheader("Accept", "*/*")
        client.endheaders()
        reponse = client.getresponse()
        if reponse.status != 200:
            raise ConnectionError(f"HTTP {reponse.status}")
        while time.time() - debut < duree:
            morceau = reponse.read(65536)
            if not morceau:
                break
            octets += len(morceau)
    finally:
        client.close()
    return octets, time.time() - debut


def resoudre_nom(hote):
    try:
        return socket.getaddrinfo(hote, 443, socket.AF_INET)[0][4][0]
    except Exception:
        pass
    for serveur, sni in (("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google")):
        try:
            contexte = ssl.create_default_context()
            sock = socket.create_connection((serveur, 443), timeout=8)
            s = contexte.wrap_socket(sock, server_hostname=sni)
            requete = f"GET /dns-query?name={hote}&type=A HTTP/1.1\r\nHost: {sni}\r\nAccept: application/dns-json\r\nUser-Agent: python\r\nConnection: close\r\n\r\n"
            s.sendall(requete.encode())
            reponse = b""
            while True:
                morceau = s.recv(65536)
                if not morceau:
                    break
                reponse += morceau
            s.close()
            donnees = json.loads(reponse.split(b"\r\n\r\n", 1)[1])
            for a in donnees.get("Answer", []):
                if a.get("type") == 1:
                    return a["data"]
        except Exception:
            continue
    return None


def telecharger_sur_duree(hote, chemin, duree, ip=None, port=443, tls=True):
    octets = 0
    debut = time.time()
    while True:
        restant = duree - (time.time() - debut)
        if restant <= 0:
            break
        try:
            morceaux, _ = telecharger_mesure(hote, chemin, restant + 5, ip, port, tls)
            if not morceaux:
                break
            octets += morceaux
        except Exception:
            break
    return octets, time.time() - debut


def test_vitesse(url_choisi, duree=6):
    cibles = []
    if url_choisi and url_choisi != URL_TEST:
        parties = url_choisi.split("/")
        if len(parties) >= 3:
            cibles.append((parties[2], "/" + "/".join(parties[3:])))
    cibles.append(("speed.hetzner.de", "/100MB.bin"))
    cibles.append(("speed.cloudflare.com", "/__down?bytes=10485760"))
    for hote, chemin in cibles:
        ip = resoudre_nom(hote)
        print(f"[*] Test de debit : telechargement depuis {hote}{' (' + ip + ')' if ip else ''} pendant {duree}s...")
        try:
            octets, duree_reelle = telecharger_sur_duree(hote, chemin, duree, ip)
            if octets:
                return {"serveur": hote, "mbit_s": octets * 8 / duree_reelle / 1_000_000, "octets": octets}
        except Exception:
            pass
    for ip in IPS_RECOURS:
        try:
            octets, duree_reelle = telecharger_sur_duree("speed.cloudflare.com", "/__down?bytes=10485760", duree, ip)
            if octets:
                return {"serveur": f"speed.cloudflare.com ({ip})", "mbit_s": octets * 8 / duree_reelle / 1_000_000, "octets": octets}
        except Exception:
            pass
    for ip in ["90.130.70.73", "90.130.71.9"]:
        try:
            print(f"[*] Test de debit : telechargement depuis speedtest.tele2.net ({ip}, HTTP) pendant {duree}s...")
            octets, duree_reelle = telecharger_sur_duree("speedtest.tele2.net", "/100MB.zip", duree, ip, 80, False)
            if octets:
                return {"serveur": f"speedtest.tele2.net ({ip})", "mbit_s": octets * 8 / duree_reelle / 1_000_000, "octets": octets}
        except Exception:
            pass
    print("[!] Test de debit impossible (acces Internet bloque ?)")
    return None


def afficher_resultats(appareils, passerelle):
    print()
    print("=" * 88)
    print("APAREILS CONNECTES")
    print("=" * 88)
    donnees = [("IP", "Nom", "Adresse MAC", "Constructeur", "Role")]
    for a in appareils:
        donnees.append((a["ip"], a["nom"] or "inconnu", a["mac"], constructeur(a["mac"]), a["propriete"]))
    largeurs = [max(len(row[i]) for row in donnees) for i in range(5)]
    print("-" * 88)
    for row in donnees:
        print("  ".join(row[j].ljust(largeurs[j]) for j in range(5)))
    print("-" * 88)
    if passerelle:
        print(f"Passerelle (routeur) : {passerelle}")
    print(f"Total : {len(appareils)} appareils detectes")


def main():
    parser = argparse.ArgumentParser(description="Analyse le reseau local : appareils connectes et vitesse de connexion.")
    parser.add_argument("--scan", action="store_true", help="detecte les appareils du reseau (IP, MAC, nom)")
    parser.add_argument("--vitesse", action="store_true", help="teste la vitesse de connexion Internet")
    parser.add_argument("--tout", action="store_true", help="scan + vitesse (par defaut)")
    parser.add_argument("--url", default=URL_TEST, help="fichier utilise pour le test de debit")
    parser.add_argument("--duree", type=int, default=6, help="duree du test de debit en secondes")
    parser.add_argument("--json", action="store_true", help="affiche le resultat en JSON")
    args = parser.parse_args()

    if args.tout or not (args.scan or args.vitesse):
        args.scan = args.vitesse = True

    socket.setdefaulttimeout(3)
    resultat = {"hote": socket.gethostname(), "ip": obtenir_ip_locale(), "passerelle": obtenir_passarelle(), "appareils": [], "vitesse": None}

    print(f"Hote local : {resultat['hote']} ({resultat['ip']})")
    if resultat["passerelle"]:
        print(f"Passerelle : {resultat['passerelle']}")

    if args.scan:
        resultat["appareils"] = trouver_appareils(resultat["ip"])

    if args.vitesse:
        resultat["vitesse"] = test_vitesse(args.url, args.duree)
        if resultat["vitesse"]:
            print(f"Debit de telechargement : {resultat['vitesse']['mbit_s']:.1f} Mbit/s ({resultat['vitesse']['octets'] / 1_049_576:.1f} Mo telecharges depuis {resultat['vitesse']['serveur']})")
        latence = latence_moyenne(resultat["passerelle"] or resultat["ip"])
        print(f"Latence vers la passerelle : {latence:.1f} ms" if latence else "[!] Latence non mesuree")

    if args.scan:
        afficher_resultats(resultat["appareils"], resultat["passerelle"])

    if args.json:
        print(json.dumps(resultat, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.")
        sys.exit(1)