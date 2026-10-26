# Nmap scan: a Strata connector module

Imports an Nmap scan saved as XML into one IS, as a proposal: nothing changes on the map until an
approver accepts it.

```
nmap -sV -O -oX scan.xml 10.20.0.0/24
```

- Hosts that are up are matched to the assets of the IS by IP, then by host name.
- Open ports become the listening ports of the asset's applications (one application per product Nmap
  recognised, `-sV`); applications typed by hand are kept and completed.
- The system Nmap guessed (`-O`) fills in assets that have none, when the guess is accurate enough
  (90% by default).
- Hosts missing from the map are created (a setting), in the VLAN whose range holds their IP, or in
  “To sort (Nmap scan)”; their type is guessed from their ports (domain controller, database, printer…).
- Nothing is removed: a port Nmap did not see may just have been filtered.
