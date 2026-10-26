# CSV inventory: a Strata connector module

Imports assets into one IS from a spreadsheet saved as CSV. The result is a proposal: nothing changes on
the map until an approver accepts it.

| Column (any order, any case) | Meaning |
|---|---|
| `name` (required) | Asset name; an asset of the IS with the same name, or the same IP, is updated |
| `ip` | IPv4 address; places the asset in the VLAN whose range holds it |
| `type` | server, dc, database, hypervisor, firewall, gateway, router, switch, workstation, printer, phone, ap, camera, plc, iot |
| `os`, `role`, `notes` | Free text |
| `vlan` | VLAN number or name, when the IP does not say it |
| `criticality` | 1 to 3, or low, medium, high |

Comma, semicolon or tab separators. Assets with neither a known VLAN nor an IP in a VLAN range wait in a
“To sort (CSV import)” VLAN.

It is also the example to start from when writing a module: see [MODULES.md](../../MODULES.md).
