meine zusammenfassung unseres gesprächs:
ich werde mich darauf konzentrieren, die user experience gerade für unerfahrene
user zu verbessern. es gibt aber auch noch einige dinge, die beim setup und den
einstellungen nicht richtig funktionieren.

konkrete aufgaben:

- in der navbar: home-button links oben neben dem logo, admin logout ganz nach rechts
- aus den setup- und system-dropdowns wird ein dropdown mit allen punkten
- die menüpunkte sinnvoll zusammenfassen (location, network, security,...) undneu sortieren (wichtige sachen nach oben)
- auf der hauptseite: device info -> network info, und klarstellen, in welchem wifi network man ist (z.b. "reachable as <ip_address> because you're connected to <wifi name> wifi network" oder "reachable as <ip_address> because you're connected to ethernet")
- network settings von da aus verlinken
- die wifi-konfiguration (zu anderem wifi verbinden) fixen, und so gestalten wie im hotspot auch (liste von verfügbaren netzwerken)
- "update timezone" -> "use browser timezone", und aus dem textfeld ein dropdown mit allen verfügbaren timezones machen (ich halte es für sinnvoll, das weiter drinzulassen, weil die timezone zwar über dhcp kommen sollte, aber das evtl. nicht 100% zuverlässig ist)
- die bulk aggregator selection ganz rausschmeißen
- im hotspot: erklären, wie man mit ethernet verbinden kann
- im hotspot: automatisch versuchen, mit dem device zu verbinden, wenn man das passwort eingegeben hat (statt der generischen "the device has probably joined the network")
- die hässlichen restarting/waiting pages besser machen
- tailscale automatisch installieren (im moment muss man das manuell machen)
- den rpi-imager checken: kann der unsere images kaputt machen, z.b. ssh ausmachen? ggf. immer ssh mitstarten o.ä.

weiter:

- versuchen, mit ai die perspective eines unerfahnenen users zu bekommen und vorschläge für die ui und ux
- an sinnvollen stellen das wording überarbeiten, besser erklären
- die arbeit an der firewall stellen wir erstmal nach hinten. die firewall bleibt erstmal aus, weil wir davon ausgehen, dass devices eh hinter nem router sind

- setup/system one menu
- home button
- logout to the right
- device info -> network info
- merge pages that are thematically related
- <ip address> because you're connected to <wifi name> wifi network
- <ip address> because you're connected to ethernet
- wifi setup as in hotspot
- note on hotspot: what if ethernet
- hotspot: link to .local address
- hotspot: try to automatically connect to device when connected (assume we're
  on the same wifi, explain that on the restarting page)
- update timezone -> use browser timezone
- bulk agg selection out
- restarting/waiting pages
- use ai to get the perspective of a first-time user
- rethink wording?
- check rpi-imager: do custom options work? do they break our images?
- dozzle verstecken
- automatically install tailscale
- firewall later, but include in overview whether it's active

- pages

  - location
  - network
  - security
