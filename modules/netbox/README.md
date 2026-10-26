# NetBox: a Strata connector module

Reads NetBox (REST API, NetBox 3.x and 4.x) with a read-only token, and proposes for each IS:

- **VLANs**: matched by number (or the NetBox VLAN they were imported from); the prefix tied to a VLAN
  becomes its range. Missing VLANs are created in an “Imported” zone.
- **Devices and virtual machines**: matched to the assets by the NetBox object they came from, then by
  name, then by primary IPv4 address. They fill in the address, system (platform) and role the asset
  lacks; missing ones are created in the VLAN whose range holds their IP, or in “To sort (NetBox)”,
  with a type guessed from their role.

A NetBox site goes to an IS through rules (`Lyon HQ = lyon`, or `/regex/ = id`) matched against its
name, slug and region; without a rule, the IS whose name or id appears in it. Only the statuses you
choose are read (active and staged by default). Nothing typed by hand is overwritten, nothing is
removed: the result is a proposal an approver reviews.

Token: in NetBox, *your profile › API Tokens › Add*, with *Write enabled* left off.
