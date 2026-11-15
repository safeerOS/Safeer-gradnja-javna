"""Preizkusi tools/zaupno.py (sifrirano prekrivalo v javnem repozitoriju, 15. 11. 2026).

Kljuci so samo preizkusni, v zacasni zbirki gpg (GNUPGHOME gre podprocesu z env=/parametrom domov, ne v os.environ).
"""
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import zaupno  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg ni namescen")


def _gpg(domov, *args, vhod=None):
    env = dict(os.environ, GNUPGHOME=domov)
    return subprocess.run(["gpg", "--batch", "--yes", "--no-tty", "--quiet", *args], input=vhod,
                          capture_output=True, env=env, check=True)


def _nov_kljuc(korenska):
    domov = tempfile.mkdtemp(prefix="gnupg-", dir=korenska)
    os.chmod(domov, 0o700)
    ime = "test-%s@safeer.invalid" % os.path.basename(domov)
    _gpg(domov, "--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", ime, "ed25519", "cert", "never")
    odtis = [z.split(":")[9] for z in _gpg(domov, "--list-keys", "--with-colons", ime).stdout.decode().splitlines()
             if z.startswith("fpr:")][0]
    _gpg(domov, "--passphrase", "", "--pinentry-mode", "loopback", "--quick-add-key", odtis, "cv25519", "encr", "never")
    zasebni = _gpg(domov, "--passphrase", "", "--pinentry-mode", "loopback", "--armor", "--export-secret-keys", odtis).stdout.decode()
    javni = _gpg(domov, "--armor", "--export", odtis).stdout
    return domov, odtis, zasebni, javni


@pytest.fixture(scope="module")
def korenska():
    d = tempfile.mkdtemp(prefix="zaupno-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def kljuc(korenska):
    return _nov_kljuc(korenska)


@pytest.fixture(scope="module")
def drug_kljuc(korenska):
    return _nov_kljuc(korenska)


def _surovo_sifrirano(domov, odtis, clani, izhod):
    """Sifrira tar, ki ga zaupno.pakiraj nikoli ne bi naredil (zlonamerno prekrivalo)."""
    pom = io.BytesIO()
    with tarfile.open(fileobj=pom, mode="w") as tar:
        for ime, vsebina, vrsta in clani:
            ti = tarfile.TarInfo(ime)
            if vrsta == "povezava":
                ti.type = tarfile.SYMTYPE
                ti.linkname = vsebina
                tar.addfile(ti)
            else:
                ti.size = len(vsebina)
                tar.addfile(ti, io.BytesIO(vsebina))
    _gpg(domov, "--trust-model", "always", "-r", odtis, "-o", str(izhod), "--encrypt", vhod=pom.getvalue())


def test_pot_tja_in_nazaj_ohrani_vsebino(tmp_path, kljuc):
    domov, odtis, zasebni, _ = kljuc
    vir = tmp_path / "vir"
    (vir / "packaging" / "webkit").mkdir(parents=True)
    (vir / "packaging" / "webkit" / "a.patch").write_bytes(b"--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n")
    (vir / "packaging" / "g.sh").write_text("#!/bin/sh\n")
    os.chmod(vir / "packaging" / "g.sh", 0o755)
    izhod = tmp_path / "p.tar.gpg"
    assert zaupno.pakiraj(vir, izhod, odtis, domov=domov) == 2
    assert b"--- a" not in izhod.read_bytes()                       # v sifriranem ni besedila prekrivala
    cilj = tmp_path / "cilj"
    assert zaupno.razpakiraj(izhod, cilj, kljuc=zasebni) == 2
    assert (cilj / "packaging/webkit/a.patch").read_bytes() == (vir / "packaging/webkit/a.patch").read_bytes()
    assert os.access(cilj / "packaging/g.sh", os.X_OK)


def test_napacen_kljuc_ne_odsifrira_in_ne_izpise_kljuca(tmp_path, kljuc, drug_kljuc):
    domov, odtis, _, _ = kljuc
    vir = tmp_path / "vir"
    (vir / "packaging").mkdir(parents=True)
    (vir / "packaging" / "a").write_text("x")
    izhod = tmp_path / "p.gpg"
    zaupno.pakiraj(vir, izhod, odtis, domov=domov)
    with pytest.raises(zaupno.NapakaZaupno) as e:
        zaupno.razpakiraj(izhod, tmp_path / "cilj", kljuc=drug_kljuc[2])
    assert "PRIVATE KEY" not in str(e.value)
    assert not (tmp_path / "cilj").exists()


def test_brez_kljuca_v_okolju_pade(tmp_path, kljuc):
    domov, odtis, _, _ = kljuc
    vir = tmp_path / "vir"
    (vir / "packaging").mkdir(parents=True)
    (vir / "packaging" / "a").write_text("x")
    izhod = tmp_path / "p.gpg"
    zaupno.pakiraj(vir, izhod, odtis, domov=domov)
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.razpakiraj(izhod, tmp_path / "cilj", kljuc="")


@pytest.mark.parametrize("ime", ["../zunaj.txt", "packaging/../../zunaj.txt", "/etc/passwd", "core/x.py", "packaging\\a"])
def test_nevarna_pot_zavrnjena_in_nic_se_ne_zapise(tmp_path, kljuc, ime):
    domov, odtis, zasebni, _ = kljuc
    izhod = tmp_path / "z.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/dober.txt", b"ok", "datoteka"), (ime, b"zlo", "datoteka")], izhod)
    cilj = tmp_path / "cilj"
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.razpakiraj(izhod, cilj, kljuc=zasebni)
    assert not (cilj / "packaging" / "dober.txt").exists()          # preverba vseh clenov PRED prvim zapisom
    assert not (tmp_path / "zunaj.txt").exists()


def test_simbolna_povezava_zavrnjena(tmp_path, kljuc):
    domov, odtis, zasebni, _ = kljuc
    izhod = tmp_path / "z.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/povezava", "/etc/passwd", "povezava")], izhod)
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.razpakiraj(izhod, tmp_path / "cilj", kljuc=zasebni)


def test_obstojeca_simbolna_povezava_v_cilju_ne_vodi_ven(tmp_path, kljuc):
    domov, odtis, zasebni, _ = kljuc
    izhod = tmp_path / "z.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/a.txt", b"zlo", "datoteka")], izhod)
    cilj = tmp_path / "cilj"
    cilj.mkdir()
    zunaj = tmp_path / "zunaj"
    zunaj.mkdir()
    os.symlink(zunaj, cilj / "packaging")                          # napadalec je pred razpakiranjem postavil povezavo
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.razpakiraj(izhod, cilj, kljuc=zasebni)
    assert not (zunaj / "a.txt").exists()


def test_izhodni_artefakt_samo_z_javnim_kljucem(tmp_path, kljuc, korenska):
    domov, odtis, zasebni, javni = kljuc
    # "tekac": zbirka samo z javnim kljucem - sifrira lahko, prebrati ne
    tekac = tempfile.mkdtemp(prefix="gnupg-tekac-", dir=korenska)
    os.chmod(tekac, 0o700)
    _gpg(tekac, "--import", vhod=javni)
    deb = tmp_path / "paket.deb"
    deb.write_bytes(os.urandom(4096))
    sif = tmp_path / "paket.deb.gpg"
    zaupno.sifriraj(deb, sif, odtis, domov=tekac)
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.odsifriraj(sif, tmp_path / "poskus", domov=tekac)    # tekac ne more prebrati nazaj
    zaupno.odsifriraj(sif, tmp_path / "nazaj", domov=domov)         # lastnik lahko
    assert (tmp_path / "nazaj").read_bytes() == deb.read_bytes()


def test_cli_brez_kljuca_vrne_2_in_napisi_napako(tmp_path):
    r = subprocess.run([sys.executable, str(Path(zaupno.__file__)), "razpakiraj", str(tmp_path / "ni"), str(tmp_path / "c")],
                       capture_output=True, env={k: v for k, v in os.environ.items() if k != "ZAUPNO_KLJUC"})
    assert r.returncode == 2 and b"ZAUPNO_KLJUC" in r.stderr
