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
PRIVZETE_PREDPONE = ("packaging/", "tests/")


class NapakaZaupno(Exception):
    pass


def _gpg(args: list[str], domov: str | None, vhod: bytes | None = None) -> subprocess.CompletedProcess:
    # Okolje podprocesu z env= (pravilo: v procesu z nitmi os.environ ne spreminjamo).
    env = dict(os.environ)
    env.pop("ZAUPNO_KLJUC", None)
    if domov:
        env["GNUPGHOME"] = domov
    return subprocess.run(["gpg", "--batch", "--yes", "--no-tty", "--quiet", *args], input=vhod,
                          capture_output=True, env=env, check=False)


def _varna_pot(ime: str, predpone: tuple[str, ...]) -> str:
    p = PurePosixPath(ime)
    if p.is_absolute() or ".." in p.parts or ime.startswith(("/", "\\")) or "\\" in ime or "\x00" in ime:
        raise NapakaZaupno("nevarna pot v prekrivalu: %r" % ime)
    s = p.as_posix()
    if s in ("", "."):
        raise NapakaZaupno("prazna pot v prekrivalu")
    if not any(s.startswith(pr) for pr in predpone):
        raise NapakaZaupno("pot zunaj dovoljenih predpon: %r" % ime)
    return s


def pakiraj(mapa: Path, izhod: Path, prejemnik: str, domov: str | None = None) -> int:
    mapa = Path(mapa)
    datoteke = sorted(p for p in mapa.rglob("*") if p.is_file() and not p.is_symlink())
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
        raise NapakaZaupno("gpg --encrypt: " + r.stderr.decode("utf-8", "replace")[:300])
    return len(datoteke)


def _odsifriraj_tok(vhod: Path, kljuc: str) -> bytes:
    osnova = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    domov = tempfile.mkdtemp(prefix="zaupno-", dir=osnova)
    try:
        os.chmod(domov, 0o700)
        r = _gpg(["--import"], domov, kljuc.encode("utf-8"))
        if r.returncode != 0:
            raise NapakaZaupno("uvoz kljuca ni uspel")        # izpisa gpg ne kazemo: lahko vsebuje dele kljuca
        r = _gpg(["--decrypt", str(vhod)], domov)
        if r.returncode != 0:
            raise NapakaZaupno("odsifriranje ni uspelo (napacen kljuc ali pokvarjena datoteka)")
        return r.stdout
    finally:
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
                raise NapakaZaupno("nedovoljena vrsta clena (povezava ali naprava): %r" % c.name)
            skupaj += c.size
            if skupaj > NAJVEC_BAJTOV:
                raise NapakaZaupno("prekrivalo je preveliko")
            rel = _varna_pot(c.name, predpone)
            ciljna = (cilj / rel).resolve()
            if cilj not in ciljna.parents:
                raise NapakaZaupno("pot uide iz ciljne mape: %r" % c.name)
            nacrt.append((c, ciljna))
        for c, ciljna in nacrt:                       # sele po preverbi VSEH clenov se kaj zapise
            ciljna.parent.mkdir(parents=True, exist_ok=True)
            if ciljna.is_symlink():
                ciljna.unlink()
            f = tar.extractfile(c)
            assert f is not None
            with open(ciljna, "wb") as g:
                shutil.copyfileobj(f, g)
            os.chmod(ciljna, 0o755 if c.mode & stat.S_IXUSR else 0o644)
    return len(nacrt)


def sifriraj(vhod: Path, izhod: Path, prejemnik: str, domov: str | None = None) -> None:
    r = _gpg(["--trust-model", "always", "--compress-algo", "none", "-r", prejemnik, "-o", str(izhod),
              "--encrypt", str(vhod)], domov)
    if r.returncode != 0:
        raise NapakaZaupno("gpg --encrypt: " + r.stderr.decode("utf-8", "replace")[:300])


def odsifriraj(vhod: Path, izhod: Path, domov: str | None = None) -> None:
    r = _gpg(["-o", str(izhod), "--decrypt", str(vhod)], domov)
    if r.returncode != 0:
        raise NapakaZaupno("gpg --decrypt: " + r.stderr.decode("utf-8", "replace")[:300])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="ukaz", required=True)
    a = sp.add_parser("pakiraj"); a.add_argument("mapa"); a.add_argument("izhod"); a.add_argument("prejemnik")
    b = sp.add_parser("razpakiraj"); b.add_argument("vhod"); b.add_argument("cilj")
    b.add_argument("--dovoli", nargs="+", default=list(PRIVZETE_PREDPONE))
    c = sp.add_parser("sifriraj"); c.add_argument("vhod"); c.add_argument("izhod"); c.add_argument("prejemnik")
    d = sp.add_parser("odsifriraj"); d.add_argument("vhod"); d.add_argument("izhod")
    n = ap.parse_args(argv)
    try:
        if n.ukaz == "pakiraj":
            print("zapakiranih datotek: %d" % pakiraj(Path(n.mapa), Path(n.izhod), n.prejemnik))
        elif n.ukaz == "razpakiraj":
            print("razpakiranih datotek: %d" % razpakiraj(Path(n.vhod), Path(n.cilj), tuple(n.dovoli)))
        elif n.ukaz == "sifriraj":
            sifriraj(Path(n.vhod), Path(n.izhod), n.prejemnik)
        else:
            odsifriraj(Path(n.vhod), Path(n.izhod))
    except NapakaZaupno as e:
        print("NAPAKA: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
