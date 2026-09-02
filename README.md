# Notrufanlagen Wartung – Version 3

Web-App für die Wartung von Notrufanlagen mit den Stammdaten **Haus → Station → Zimmer**.

## Enthalten
- 27 Häuser aus KWP Nord + KWP Süd
- 3.296 eindeutige Stammdaten-Zuordnungen Haus/Station/Zimmer
- Haus- und Stationsauswahl als abhängige Dropdowns
- Wartung wird direkt aus der ausgewählten Station gestartet
- Nur die zu dieser Station hinterlegten Zimmer werden angelegt
- Prüfwerte ZT, ZL, RT B1, RT B2, RT B3, RT Bad, PT Bad, ZT Bad, AT Bad
- OK / NOK bzw. OK / NOK / nicht ausgeführt
- Zwischenspeichern
- Wartungshistorie
- Digitale Unterschrift per Finger/Stift/Maus
- PDF-Wartungsprotokoll
- Automatische NOK-Zählung
- Kein Anlagennummernfeld
- Keine Hausbezeichnung
- Keine Zimmer-Kurzbezeichnung

## Login für den Test
- Benutzer: `admin`
- Passwort: `admin123`

## Render
Build command:
`pip install -r requirements.txt`

Start command:
`uvicorn app.main:app --host 0.0.0.0 --port $PORT`

Für die Session sollte in Render `SESSION_SECRET` als Environment Variable gesetzt werden. `render.yaml` erzeugt diesen Wert automatisch.

Hinweis: Für einen echten Produktivbetrieb mit mehreren Benutzern sollte später PostgreSQL statt SQLite verwendet werden.
