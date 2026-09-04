# Notrufanlagen Wartung – V25

## Mobile Wartungsansicht
- Zimmerübersicht mit funktionierendem Fortschritts-Counter und Fortschrittsbalken.
- Zimmerkarten öffnen zuverlässig die Komponentenprüfung.
- Komponentenstatus ✓ OK / ! NOK / — nicht ausgeführt sind direkt anklickbar.
- Der ausgewählte Status wird sofort in der Wartung übernommen.
- Bei NOK erscheint unmittelbar das Feld „Details zum Mangel“.
- Änderungen werden automatisch im Hintergrund gespeichert.
- Der Fortschrittsbalken wird nicht separat gespeichert, sondern nach dem Laden zuverlässig aus den gespeicherten Komponentenstatus neu berechnet.
- Zusätzlich bleibt „Zwischenspeichern“ verfügbar.
- Navigation zwischen Zimmern und zurück zur Zimmerübersicht.

## Anmeldung
- Das bereitgestellte Notrufanlagen-Wartungslogo wird auf der Login-Seite über dem Anmeldeformular angezeigt.

## Deployment
```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```
