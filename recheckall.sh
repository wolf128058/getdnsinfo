#!/bin/bash

## filename     recheckall.sh
## description: run the python-script getdnsinfo.py
##              for each basename of the json-files in ./data
## author:      jonas.hess@herbac-international.de
## =======================================================================

# 1. Prüfen, ob das venv Verzeichnis existiert
if [ ! -d "venv" ]; then
    echo "==> Erstelle Virtual Environment..."
    python3 -m venv venv
    
    echo "==> Aktiviere venv und installiere Requirements..."
    source venv/bin/activate
    pip install --upgrade pip
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        echo "WARNUNG: requirements.txt nicht gefunden. Überspringe Installation."
    fi
else
    echo "==> venv bereits vorhanden. Aktiviere..."
    source venv/bin/activate
fi

# 2. Ausführung der Scripte im aktivierten Environment
for filename in data/*.json; do
    echo
    echo "==> "$(basename "$filename" .json)
    # Hier wird das python3 aus dem venv genutzt
    ./venv/bin/python getdnsinfo.py -d $(basename "$filename" .json)
    echo
done

echo "==> Führe Reset-Script aus..."
./venv/bin/python reset-nonchanges.py

# Optional: venv am Ende wieder deaktivieren
deactivate