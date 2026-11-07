# CSV VLANs: a Strata connector module

Brings VLANs into one IS from a spreadsheet saved as CSV, **choosing which VLANs and the zone of each**.
The result is a proposal: nothing changes on the map until an approver accepts it.

1. *Collaboration › Connectors › CSV VLANs › Import VLANs from a CSV*: the IS and the file.
2. Strata lists the VLANs of the file: tick those to bring (the new ones are ticked), filter, and choose
   the zone of each, or of all the ticked ones at once: a zone of the IS, a zone named in the file, or a
   new one.
3. *Import*: the proposal holds the IS with those VLANs; an approver reviews it in *Proposals*.

| Column (any order, any case, English or French) | Meaning |
|---|---|
| `number`, `vlan`, `vid`, `numéro` (required) | VLAN number, 1 to 4094 (`VLAN 10` is read as 10) |
| `name`, `nom`, `description` | VLAN name (`VLAN <number>` when empty) |
| `cidr`, `subnet`, `network`, `réseau`, `range` | Address range, such as `10.20.0.0/24` |
| `zone`, `group` (optional) | The zone suggested for the VLAN; created when the IS has none of that name |

Without a header line, the columns are told apart by what they hold: ranges, numbers, and names, in any
order (`10.20.0.0/24;Servers;20` works). Commas, semicolons or tabs.

A VLAN already in the IS (same number) starts unticked; ticked, its name, range and zone are updated. The
same file imported again gives the same proposal, and none when the IS already matches.

From a script, without a choice (`picks` left out), every VLAN of the file is brought, in the zone the file
gives, else the *default zone* of the settings, else the top zone; those already in the IS are left alone
unless *update the VLANs already in the IS* is on. With a choice:

```bash
jq -n --rawfile x vlans.csv '{wait: true, file: {name: "vlans.csv", text: $x}, overrides: {site: "lyon"},
  picks: {"300": {zone: "new:Lab"}, "301": {zone: "new:Lab"}, "20": {}}}' |
  curl -sS -H "Authorization: Bearer $STRATA_TOKEN" -H 'Content-Type: application/json' -H 'X-Requested-With: strata' \
    -X POST https://strata.example.lan/api/connectors/csv-vlans/run --data-binary @-
```

`POST /api/connectors/csv-vlans/preview` with the same `file` and `overrides` answers the VLANs of the
file, as the import window shows them. Needs Strata 0.11 or later for the choice; an older Strata
imports every VLAN of the file.
