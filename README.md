# Notrufanlagen Wartung – V11

FastAPI-Webapp zur Wartung von Rufanlagen mit VCIP-Import.

## Änderungen in V11
- Abschlussdatum im PDF: `TT.MM.JJJJ` ohne Uhrzeit.
- Prüfername steht im PDF direkt unter der Unterschrift in der Form `Name des Prüfers: ...`.
- Überarbeiteter Hinweis unter dem PDF-Titel.
- Erweiterte Abkürzungslegende neben der OK/NOK/nicht-ausgeführt-Legende.
- Seitenzahl rechts unten, z. B. `Seite 1/2`.
- Neues Feld `Art der Überprüfung` mit `Inspektion`, `Wartung`, `Instandhaltung`.
- Der PDF-Titel passt sich automatisch an die gewählte Art der Überprüfung an.
- VCIP-Stationen werden weiterhin über ihre eindeutige Systembau-/VCIP-Identität getrennt, auch bei identischen Stationsnamen.
