#!/bin/bash
# Zaupna gradnja (15. 11. 2026): zazene ukaz, CELOTEN izpis shrani v datoteko (ta gre sifrirana v artefakt), v javni
# dnevnik teka pa pise samo zaporedno stevilko koraka ninja (vsak 200.; skupnega stevila m NE: ta pove, koliko enot ima
# neobjavljeno delo) in izid. Razlog: napaka prevajalca bi v javni dnevnik izpisala vrstico izvorne kode neobjavljenega dela.
# Raba: zaupno_zagon.sh DNEVNIK UKAZ [ARGUMENTI...]
set -u
[ $# -ge 2 ] || { echo "raba: zaupno_zagon.sh DNEVNIK UKAZ [ARGUMENTI...]" >&2; exit 64; }
LOG="$1"; shift
mkdir -p "$(dirname "$LOG")"
( "$@" 2>&1 ) | tee "$LOG" | grep --line-buffered -oE '^\[[0-9]+/' | sed -u 's/[^0-9]//g' | awk 'NR % 200 == 0 { print "korak " $1; fflush() }'
RC=${PIPESTATUS[0]}
echo "izid ukaza: ${RC} (celoten dnevnik je v sifriranem artefaktu)"
exit "$RC"
