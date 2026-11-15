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


def test_povezava_znotraj_cilja_na_kodo_ki_tece_pozneje_je_zavrnjena(tmp_path, kljuc):
    """MM3: packaging/x -> ../tools/z.py je znotraj cilja, zato resolve() ni ujel prepisa tools/z.py."""
    domov, odtis, zasebni, _ = kljuc
    izhod = tmp_path / "z.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/x", b"zlo", "datoteka")], izhod)
    cilj = tmp_path / "cilj"
    (cilj / "tools").mkdir(parents=True)
    (cilj / "packaging").mkdir()
    (cilj / "tools" / "z.py").write_text("izvirnik")
    os.symlink("../tools/z.py", cilj / "packaging" / "x")
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.razpakiraj(izhod, cilj, kljuc=zasebni)
    assert (cilj / "tools" / "z.py").read_text() == "izvirnik"


def test_povezava_na_mapo_na_poti_je_zavrnjena(tmp_path, kljuc):
    domov, odtis, zasebni, _ = kljuc
    izhod = tmp_path / "z.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/webkit-deb/zagon.sh", b"zlo", "datoteka")], izhod)
    cilj = tmp_path / "cilj"
    (cilj / "tools").mkdir(parents=True)
    (cilj / "packaging").mkdir()
    os.symlink("../tools", cilj / "packaging" / "webkit-deb")
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.razpakiraj(izhod, cilj, kljuc=zasebni)
    assert not (cilj / "tools" / "zagon.sh").exists()


def test_napaka_ne_izpise_imena_clena(tmp_path, kljuc):
    """MM4: imena poti neobjavljenega dela ne smejo v javni dnevnik."""
    domov, odtis, zasebni, _ = kljuc
    izhod = tmp_path / "z.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/dober.txt", b"ok", "datoteka"), ("tajno/ime.c", b"zlo", "datoteka")], izhod)
    with pytest.raises(zaupno.NapakaZaupno) as e:
        zaupno.razpakiraj(izhod, tmp_path / "cilj", kljuc=zasebni)
    assert "tajno" not in str(e.value) and "ime.c" not in str(e.value)
    r = subprocess.run([sys.executable, str(Path(zaupno.__file__)), "razpakiraj", str(izhod), str(tmp_path / "c2")],
                       capture_output=True, env=dict(os.environ, ZAUPNO_KLJUC=zasebni), check=False)
    assert r.returncode == 2
    assert b"tajno" not in r.stdout + r.stderr and b"ime.c" not in r.stdout + r.stderr


def test_pakiraj_ne_sledi_povezavam_na_mape(tmp_path, kljuc):
    """MM11: stage/povezava -> mapa zunaj ne sme spraviti tujih datotek v prekrivalo ali izhod."""
    domov, odtis, zasebni, _ = kljuc
    zunaj = tmp_path / "zunaj"
    zunaj.mkdir()
    (zunaj / "skrivnost.txt").write_text("tuje")
    vir = tmp_path / "vir"
    (vir / "packaging").mkdir(parents=True)
    (vir / "packaging" / "a").write_text("x")
    os.symlink(zunaj, vir / "packaging" / "povezava")
    izhod = tmp_path / "p.gpg"
    assert zaupno.pakiraj(vir, izhod, odtis, domov=domov) == 1
    cilj = tmp_path / "cilj"
    zaupno.razpakiraj(izhod, cilj, kljuc=zasebni)
    assert not (cilj / "packaging" / "povezava").exists()


def test_nepreberno_loci_berljiv_izhod_od_nepreberljivega(tmp_path, kljuc, drug_kljuc):
    """MM2: izhod za LOCEN par je s kljucem iz okolja nepreberen (No secret key); za isti par je berljiv."""
    domov, odtis, zasebni, _ = kljuc
    drug_domov, drug_odtis, drug_zasebni, _ = drug_kljuc
    dat = tmp_path / "a.bin"
    dat.write_bytes(b"izhod")
    za_drugega = tmp_path / "a.gpg"
    zaupno.sifriraj(dat, za_drugega, drug_odtis, domov=drug_domov)
    assert zaupno.nepreberno(za_drugega, kljuc=zasebni) is True
    za_istega = tmp_path / "b.gpg"
    zaupno.sifriraj(dat, za_istega, odtis, domov=domov)
    assert zaupno.nepreberno(za_istega, kljuc=zasebni) is False
    (tmp_path / "c.gpg").write_bytes(b"to ni gpg")
    assert zaupno.nepreberno(tmp_path / "c.gpg", kljuc=zasebni) is False      # drug vzrok ni dokaz


def test_bomba_stiskanja_se_ustavi_pri_meji_izhoda(tmp_path, kljuc, monkeypatch):
    """OO5: majhna sifrirana datoteka, ki se razsiri v veliko vec, ne sme zapolniti pomnilnika (gpg --max-output)."""
    domov, odtis, zasebni, _ = kljuc
    monkeypatch.setattr(zaupno, "NAJVEC_IZHODA_GPG", 1_000_000)
    izhod = tmp_path / "bomba.tar.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/nic.bin", bytes(3_000_000), "datoteka")], izhod)
    assert izhod.stat().st_size < 100_000                           # res je stisnjeno (3 MB ničel)
    with pytest.raises(zaupno.NapakaZaupno, match="odsifriranje ni uspelo"):    # vzrok je meja gpg, ne razclenitev tara
        zaupno.razpakiraj(izhod, tmp_path / "cilj", kljuc=zasebni)
    assert not (tmp_path / "cilj" / "packaging").exists()
    # pozitivna kontrola (QQ6): ista datoteka brez nizke meje se razpakira, torej je zavrnitev res zaradi meje
    monkeypatch.setattr(zaupno, "NAJVEC_IZHODA_GPG", 10_000_000)
    assert zaupno.razpakiraj(izhod, tmp_path / "cilj2", kljuc=zasebni) == 1
    assert (tmp_path / "cilj2" / "packaging" / "nic.bin").stat().st_size == 3_000_000


def test_lokalno_odsifriranje_ima_tesno_mejo_izhoda(tmp_path, kljuc):
    """QQ3/RR5: izhod brez stiskanja ni vecji od sifrirane datoteke; stiskalna bomba se ustavi in ne pusti delnega izhoda."""
    domov, odtis, zasebni, _ = kljuc
    bomba = tmp_path / "bomba.gpg"
    _surovo_sifrirano(domov, odtis, [("packaging/nic.bin", bytes(3_000_000), "datoteka")], bomba)
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno.odsifriraj(bomba, tmp_path / "ven.bin", domov=domov)
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith("ven") or p.name.startswith(".odsifrirano")] == []
    # pozitivna kontrola: zakonit izhod (nasa sifriraj, brez stiskanja) se odsifrira v celoti
    podatki = os.urandom(3_000_000)
    (tmp_path / "izhod.bin").write_bytes(podatki)
    zaupno.sifriraj(tmp_path / "izhod.bin", tmp_path / "izhod.gpg", odtis, domov=domov)
    zaupno.odsifriraj(tmp_path / "izhod.gpg", tmp_path / "nazaj.bin", domov=domov)
    assert (tmp_path / "nazaj.bin").read_bytes() == podatki
    assert oct((tmp_path / "nazaj.bin").stat().st_mode & 0o777) == "0o600"


def test_gpg_tece_v_c_lokali_ne_glede_na_jezik_sistema(monkeypatch):
    """OO7: presoja v `nepreberno` temelji na angleskem besedilu gpg; podproces zato vedno dobi LC_ALL=C brez LANGUAGE."""
    videno = {}

    def lazni_zagon(ukaz, **kw):
        videno.update(kw["env"])
        return subprocess.CompletedProcess(ukaz, 0, b"", b"")

    monkeypatch.setenv("LANG", "sl_SI.UTF-8")
    monkeypatch.setenv("LC_ALL", "sl_SI.UTF-8")
    monkeypatch.setenv("LANGUAGE", "sl")
    monkeypatch.setenv("ZAUPNO_KLJUC", "ne-sme-do-gpg")                # brez te nastavitve je spodnja trditev prazna (QQ7)
    monkeypatch.setattr(zaupno.subprocess, "run", lazni_zagon)
    zaupno._gpg(["--version"], None)
    assert videno["LC_ALL"] == "C"
    assert "LANGUAGE" not in videno
    assert "ZAUPNO_KLJUC" not in videno


def test_predpona_brez_poslevnice_ne_dovoli_sorodne_mape():
    assert zaupno._varna_pot("packaging/a.sh", ("packaging",)) == "packaging/a.sh"
    with pytest.raises(zaupno.NapakaZaupno):
        zaupno._varna_pot("packaging-zlo/a.sh", ("packaging",))


# --- delovni tok GitHub Actions (PP1/PP9/PP10, slepi pregled 15. 11. 2026): skrivnost samo tam, kjer jo smemo uporabiti ---

def _yaml():
    try:
        import yaml
    except ImportError:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("v CI mora biti PyYAML (apt: python3-yaml), sicer se preverba toka tiho preskoci")
        pytest.skip("PyYAML ni nameščen")
    return yaml


def _tezave_toka(besedilo: str) -> list:
    """Pravila toka (PP1/PP9/PP10, RR6): sprozilec samo workflow_dispatch; vsak posel ima isti pogoj (privzeta veja, lastnik,
    triggering_actor); posel, ki vidi skrivnost, ima environment natanko `zaupno`; skrivnost samo v `env` koraka z `run`
    (ne v poslu, ne v toku, ne v `with`, ne v koraku `uses`), ta korak ne dela se drugih stvari; brez `secrets: inherit`."""
    yaml = _yaml()
    tok = yaml.safe_load(besedilo)
    tezave = []
    sproziloci = tok.get("on", tok.get(True))
    if set(sproziloci if isinstance(sproziloci, (dict, list)) else [sproziloci]) != {"workflow_dispatch"}:
        tezave.append("tok: sprozilec ni samo workflow_dispatch")
    if "secrets" in yaml.safe_dump(tok.get("env", {})):
        tezave.append("tok: skrivnost v env toka")
    if "toJSON(secrets" in besedilo or "secrets: inherit" in besedilo:
        tezave.append("tok: toJSON(secrets) ali secrets: inherit")
    for ime, posel in tok["jobs"].items():
        pogoj = str(posel.get("if", ""))
        if "triggering_actor" not in pogoj or "default_branch" not in pogoj:
            tezave.append("%s: pogoj brez triggering_actor ali privzete veje" % ime)
        if "uses" in posel:
            tezave.append("%s: posel kliče zunanji tok" % ime)
        if "ZAUPNO_KLJUC" not in yaml.safe_dump(posel):
            continue
        if not posel.get("environment"):
            tezave.append("%s: brez environment" % ime)
        elif posel.get("environment") != "zaupno":
            tezave.append("%s: environment ni zaupno" % ime)
        if "ZAUPNO_KLJUC" in yaml.safe_dump(posel.get("env", {})):
            tezave.append("%s: skrivnost v env posla" % ime)
        for k in posel.get("steps", []):
            if "ZAUPNO_KLJUC" not in yaml.safe_dump(k):
                continue
            if "run" not in k or "uses" in k or "ZAUPNO_KLJUC" in yaml.safe_dump(k.get("with", {})):
                tezave.append("%s: skrivnost v koraku brez run ali v with" % ime)
            elif "sha256sum" in k["run"] or "cat " in k["run"]:
                tezave.append("%s: korak s skrivnostjo dela se druge stvari" % ime)
    return tezave


_DOBER = """
on:
  workflow_dispatch:
jobs:
  a:
    environment: zaupno
    if: ${{ github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && github.actor == github.repository_owner && github.triggering_actor == github.repository_owner }}
    steps:
      - run: python3 tools/zaupno.py razpakiraj x y
        env:
          ZAUPNO_KLJUC: ${{ secrets.ZAUPNO_KLJUC }}
"""


def test_tok_preverba_ujame_napake():
    assert _tezave_toka(_DOBER) == []
    assert _tezave_toka(_DOBER.replace("    environment: zaupno\n", "")) == ["a: brez environment"]
    assert _tezave_toka(_DOBER.replace("environment: zaupno", "environment: drugo")) == ["a: environment ni zaupno"]
    assert _tezave_toka(_DOBER.replace(" && github.triggering_actor == github.repository_owner", "")) == [
        "a: pogoj brez triggering_actor ali privzete veje"]
    assert _tezave_toka(_DOBER.replace("      - run: python3 tools/zaupno.py razpakiraj x y", "      - run: sha256sum -c a")) == [
        "a: korak s skrivnostjo dela se druge stvari"]
    assert _tezave_toka(_DOBER.replace("      - run: python3 tools/zaupno.py razpakiraj x y", "      - uses: tuja/akcija@v1")) == [
        "a: skrivnost v koraku brez run ali v with"]
    assert _tezave_toka(_DOBER.replace("  workflow_dispatch:", "  workflow_dispatch:\n  pull_request_target:")) == [
        "tok: sprozilec ni samo workflow_dispatch"]
    assert _tezave_toka(_DOBER.replace("on:\n", "env:\n  X: ${{ secrets.ZAUPNO_KLJUC }}\non:\n")) == ["tok: skrivnost v env toka"]
    assert _tezave_toka(_DOBER + "  b:\n    steps:\n      - run: echo\n") == ["b: pogoj brez triggering_actor ali privzete veje"]


def test_pravi_tok_je_v_redu():
    pot = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "zaupna-webkit.yml"
    if not pot.is_file():
        pytest.skip("delovnega toka ni v tem drevesu (je samo v javnem repozitoriju za gradnjo)")
    assert _tezave_toka(pot.read_text(encoding="utf-8")) == []
