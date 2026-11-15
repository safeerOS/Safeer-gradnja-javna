#!/usr/bin/env python3
"""Zaupna gradnja v javnem repozitoriju: neobjavljeno delo je v repozitoriju samo SIFRIRANO (gpg), tekac ga odsifrira.

Zakaj (lastnik, 15. 11. 2026): gradnja WebKita na GitHubu naj ne zaseda nasih racunalnikov, neobjavljeno delo pa
ostane zaupno, dokler ni pripravljeno za objavo. Isti postopek je vaja za prihodnje projekte s skrivnostmi.

Dejanja (samo standardna knjiznica + gpg):
  pakiraj     <mapa> <izhod.tar.gpg> <prejemnik>   - datoteke mape (relativne poti) -> tar -> gpg za javni kljuc
  razpakiraj  <vhod.tar.gpg> <cilj> [--dovoli PRED ...]
              - zasebni kljuc je SAMO v okolju ZAUPNO_KLJUC (armored); GNUPGHOME v /dev/shm (ali mktemp), po koncu
                pobrisan; tar se prebere iz toka in vsak clen preveri (samo datoteke in mape, relativna pot brez
                .., predpone iz seznama dovoljenih, omejitev velikosti) - prekrivalo ne sme pisati kamorkoli
  sifriraj    <datoteka> <izhod.gpg> <prejemnik>   - izhodni artefakt (samo javni kljuc: tekac ga ne more prebrati nazaj)
  odsifriraj  <datoteka.gpg> <izhod>               - lokalno, zasebni kljuc v gpg zbirki uporabnika

Zasebni kljuc se nikoli ne izpise (ne v dnevnik, ne v napako).
"""
from __future__ import annotations

import argparse
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

NAJVEC_CLENOV = 5000
NAJVEC_BAJTOV = 512 * 1024 * 1024
#: OO5: gpg sam ustavi odsifriranje, ko bi izhod presegel mejo (stisnjen paket bi sicer zapolnil pomnilnik), rezerva za glave tar
NAJVEC_IZHODA_GPG = NAJVEC_BAJTOV + 8 * 1024 * 1024
PRIVZETE_PREDPONE = ("packaging/", "tests/")


class NapakaZaupno(Exception):
    pass


def _gpg(args: list[str], domov: str | None, vhod: bytes | None = None) -> subprocess.CompletedProcess:
    # Okolje podprocesu z env= (pravilo: v procesu z nitmi os.environ ne spreminjamo).
    env = dict(os.environ)
    env.pop("ZAUPNO_KLJUC", None)
    # OO7: sporocila gpg so prevedena po jeziku sistema; presoja po besedilu (»No secret key«) velja samo v C lokali.
    env["LC_ALL"] = "C"
    env.pop("LANGUAGE", None)
    if domov:
        env["GNUPGHOME"] = domov
    return subprocess.run(["gpg", "--batch", "--yes", "--no-tty", "--quiet", *args], input=vhod,
                          capture_output=True, env=env, check=False)


def _varna_pot(ime: str, predpone: tuple[str, ...]) -> str:
    p = PurePosixPath(ime)
    if p.is_absolute() or ".." in p.parts or ime.startswith(("/", "\\")) or "\\" in ime or "\x00" in ime:
        raise NapakaZaupno("nevarna pot v prekrivalu")
    s = p.as_posix()
    if s in ("", "."):
        raise NapakaZaupno("prazna pot v prekrivalu")
    if not any(s.startswith(pr.rstrip("/") + "/") for pr in predpone):     # OO11: »packaging« ne dovoli »packaging-x/«
        raise NapakaZaupno("pot zunaj dovoljenih predpon")
    return s


def _brez_povezav(cilj: Path, rel: str) -> Path:
    """Pot v ciljni mapi, v kateri NI nobene simbolne povezave (MM3, neodvisni pregled 15. 11. 2026): resolve() bi povezavo
    v ze obstojecem drevesu razresil znotraj cilja (packaging/x -> ../tools/zaupno.py) in prekrivalo bi prepisalo kodo,
    ki tece pozneje v koraku s skrivnostjo. Vsak obstojeci del poti mora biti navadna mapa ali (zadnji) navadna datoteka."""
    p = cilj
    deli = PurePosixPath(rel).parts
    for i, del_ in enumerate(deli):
        p = p / del_
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode):
            raise NapakaZaupno("simbolna povezava na poti v ciljni mapi")
        zadnji = i == len(deli) - 1
        if (zadnji and not stat.S_ISREG(st.st_mode)) or (not zadnji and not stat.S_ISDIR(st.st_mode)):
            raise NapakaZaupno("nepricakovana vrsta obstojece datoteke v ciljni mapi")
    return p


def pakiraj(mapa: Path, izhod: Path, prejemnik: str, domov: str | None = None) -> int:
    mapa = Path(mapa)
    datoteke = []
    for koren, mape, imena in os.walk(mapa, followlinks=False):      # MM11: povezave na mape se ne obiscejo
        mape[:] = [d for d in mape if not os.path.islink(os.path.join(koren, d))]
        datoteke += [Path(koren, n) for n in imena if not os.path.islink(os.path.join(koren, n))]
    datoteke.sort()
    if not datoteke:
        raise NapakaZaupno("mapa nima datotek")
    pomnilnik = io.BytesIO()
    with tarfile.open(fileobj=pomnilnik, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for p in datoteke:
            ti = tarfile.TarInfo(p.relative_to(mapa).as_posix())
            ti.size = p.stat().st_size
            ti.mtime = 0
            ti.mode = 0o755 if p.stat().st_mode & stat.S_IXUSR else 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            with p.open("rb") as f:
                tar.addfile(ti, f)
    r = _gpg(["--trust-model", "always", "--compress-algo", "none", "-r", prejemnik, "-o", str(izhod), "--encrypt"],
             domov, pomnilnik.getvalue())
    if r.returncode != 0:
        raise NapakaZaupno("gpg --encrypt ni uspel (koda %d)" % r.returncode)
    return len(datoteke)


def _odsifriraj_tok(vhod: Path, kljuc: str) -> bytes:
    osnova = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    domov = tempfile.mkdtemp(prefix="zaupno-", dir=osnova)
    try:
        os.chmod(domov, 0o700)
        r = _gpg(["--import"], domov, kljuc.encode("utf-8"))
        if r.returncode != 0:
            raise NapakaZaupno("uvoz kljuca ni uspel")        # izpisa gpg ne kazemo: lahko vsebuje dele kljuca
        r = _gpg(["--max-output", str(NAJVEC_IZHODA_GPG), "--decrypt", "--", str(vhod)], domov)
        if r.returncode != 0:
            raise NapakaZaupno("odsifriranje ni uspelo (napacen kljuc ali pokvarjena datoteka)")
        return r.stdout
    finally:
        try:      # MM6: agent bi sicer zivel dalje (kljuc brez gesla), ko gradnja ze tece kot root
            subprocess.run(["gpgconf", "--homedir", domov, "--kill", "all"], capture_output=True, check=False, timeout=15,
                           env={k: v for k, v in os.environ.items() if k != "ZAUPNO_KLJUC"})
        except (OSError, subprocess.SubprocessError):
            pass
        shutil.rmtree(domov, ignore_errors=True)


def razpakiraj(vhod: Path, cilj: Path, predpone: tuple[str, ...] = PRIVZETE_PREDPONE, kljuc: str | None = None) -> int:
    kljuc = kljuc if kljuc is not None else os.environ.get("ZAUPNO_KLJUC", "")
    if not kljuc.strip():
        raise NapakaZaupno("ZAUPNO_KLJUC ni nastavljen")
    tok = _odsifriraj_tok(Path(vhod), kljuc)
    cilj = Path(cilj).resolve()
    skupaj = 0
    with tarfile.open(fileobj=io.BytesIO(tok), mode="r:") as tar:
        clani = tar.getmembers()
        if len(clani) > NAJVEC_CLENOV:
            raise NapakaZaupno("preveliko stevilo clenov")
        nacrt = []
        for c in clani:
            if c.isdir():
                continue
            if not c.isreg():
                raise NapakaZaupno("nedovoljena vrsta clena (povezava ali naprava)")
            skupaj += c.size
            if skupaj > NAJVEC_BAJTOV:
                raise NapakaZaupno("prekrivalo je preveliko")
            rel = _varna_pot(c.name, predpone)
            ciljna = _brez_povezav(cilj, rel)
            nacrt.append((c, ciljna))
        for c, ciljna in nacrt:                       # sele po preverbi VSEH clenov se kaj zapise
            ciljna.parent.mkdir(parents=True, exist_ok=True)
            f = tar.extractfile(c)
            assert f is not None
            # O_NOFOLLOW: tudi ce se povezava pojavi med preverbo in zapisom, se ne sledi (MM3)
            fd = os.open(ciljna, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as g:
                shutil.copyfileobj(f, g)
            os.chmod(ciljna, 0o755 if c.mode & stat.S_IXUSR else 0o644)
    return len(nacrt)


def nepreberno(vhod: Path, kljuc: str | None = None) -> bool:
    """MM2: dokaz, da kljuc iz okolja (ZAUPNO_KLJUC) izhoda NE odsifrira, in da je vzrok res manjkajoci zasebni kljuc
    (»No secret key«), ne okvara gpg. Izhodi se sifrirajo za LOCEN par, katerega zasebni del ni v Actions."""
    kljuc = kljuc if kljuc is not None else os.environ.get("ZAUPNO_KLJUC", "")
    if not kljuc.strip():
        raise NapakaZaupno("ZAUPNO_KLJUC ni nastavljen")
    osnova = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    domov = tempfile.mkdtemp(prefix="zaupno-", dir=osnova)
    try:
        if _gpg(["--import"], domov, kljuc.encode("utf-8")).returncode != 0:
            raise NapakaZaupno("uvoz kljuca ni uspel")
        r = _gpg(["--max-output", str(NAJVEC_IZHODA_GPG), "--decrypt", "--", str(vhod)], domov)
        return r.returncode != 0 and b"No secret key" in r.stderr and not r.stdout
    finally:
        try:
            subprocess.run(["gpgconf", "--homedir", domov, "--kill", "all"], capture_output=True, check=False, timeout=15,
                           env={k: v for k, v in os.environ.items() if k != "ZAUPNO_KLJUC"})
        except (OSError, subprocess.SubprocessError):
            pass
        shutil.rmtree(domov, ignore_errors=True)


def sifriraj(vhod: Path, izhod: Path, prejemnik: str, domov: str | None = None) -> None:
    r = _gpg(["--trust-model", "always", "--compress-algo", "none", "-r", prejemnik, "-o", str(izhod),
              "--encrypt", "--", str(vhod)], domov)
    if r.returncode != 0:
        raise NapakaZaupno("gpg --encrypt ni uspel (koda %d)" % r.returncode)


def odsifriraj(vhod: Path, izhod: Path, domov: str | None = None) -> None:
    r = _gpg(["-o", str(izhod), "--decrypt", "--", str(vhod)], domov)
    if r.returncode != 0:
        raise NapakaZaupno("gpg --decrypt ni uspel (koda %d)" % r.returncode)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="ukaz", required=True)
    a = sp.add_parser("pakiraj"); a.add_argument("mapa"); a.add_argument("izhod"); a.add_argument("prejemnik")
    b = sp.add_parser("razpakiraj"); b.add_argument("vhod"); b.add_argument("cilj")
    b.add_argument("--dovoli", nargs="+", default=list(PRIVZETE_PREDPONE))
    c = sp.add_parser("sifriraj"); c.add_argument("vhod"); c.add_argument("izhod"); c.add_argument("prejemnik")
    d = sp.add_parser("odsifriraj"); d.add_argument("vhod"); d.add_argument("izhod")
    e = sp.add_parser("nepreberno"); e.add_argument("vhod")
    n = ap.parse_args(argv)
    try:
        if n.ukaz == "pakiraj":
            print("zapakiranih datotek: %d" % pakiraj(Path(n.mapa), Path(n.izhod), n.prejemnik))
        elif n.ukaz == "razpakiraj":
            print("razpakiranih datotek: %d" % razpakiraj(Path(n.vhod), Path(n.cilj), tuple(n.dovoli)))
        elif n.ukaz == "nepreberno":
            if not nepreberno(Path(n.vhod)):
                raise NapakaZaupno("izhod je berljiv s kljucem iz okolja ali vzrok ni manjkajoci zasebni kljuc")
            print("izhod je nepreberen s kljucem iz okolja")
        elif n.ukaz == "sifriraj":
            sifriraj(Path(n.vhod), Path(n.izhod), n.prejemnik)
        else:
            odsifriraj(Path(n.vhod), Path(n.izhod))
    except NapakaZaupno as e:
        print("NAPAKA: %s" % e, file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - javni dnevnik: samo vrsta napake, brez poti in imen (MM4)
        print("NAPAKA: nepricakovana napaka (%s)" % type(e).__name__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
