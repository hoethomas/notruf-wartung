# Notrufanlagen Wartung – V8

Web-App für Wartungen von Rufanlagen.

## V8 Änderungen
- Nach jeder Anmeldung kann der Benutzer eine `.vcip`-Datei laden.
- Die hochgeladene VCIP-Konfiguration ist benutzerspezifisch und ersetzt die zuvor aktive Konfiguration dieses Benutzers.
- Neue Wartungen können ausschließlich aus der aktuell geladenen VCIP-Programmierung gestartet werden.
- Haus → Station → Zimmer werden automatisch aus der VCIP aufgebaut.
- Die Hausbezeichnung wird nicht gekürzt; die aus der VCIP gelesene führende Bezeichnung wird unverändert gespeichert und im Dropdown angezeigt.
- Bestehende Wartungshistorie bleibt erhalten.
- Piktogramme im Wartungsmodus/PDF: ✓ OK, ! NOK, — nicht ausgeführt.
- E-Mail-Versand ist nicht enthalten.

## Demo-Benutzer
- admin / admin123
- Test1 / 1234
- Test2 / 1234
- Test3 / 1234
