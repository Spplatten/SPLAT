# Commercial licensing

SPLAT is published under the **GNU Affero General Public License v3.0** ([LICENSE](LICENSE)).
Copyright © 2026 Platten Industries. All rights reserved where not granted by that license.

The AGPL is a deliberate choice rather than a default. Read it before you build on this.

## What the AGPL gives you, free

Everything, if you are willing to be bound by it: run it, read it, change it, ship it, embed it.
There is no evaluation period, no seat count, no feature held back, and no telemetry. The daemon in
`native/splat-agent` is the whole thing, not a crippled edition of it.

## What it asks in return

If you convey a modified version, or **let anyone interact with a modified version over a network**,
you must offer those users the corresponding source of your version under the same license. That
network clause is the difference between the AGPL and the GPL, and it is the reason this license was
picked: a containment substrate's natural commercial shape is somebody else's platform running it
for their customers, and the AGPL says that arrangement is fine as long as it stays open.

Two things it does **not** ask:

- Using SPLAT to run your own workloads imposes nothing. Containing agents on your own machines, in
  your own CI, for your own company, is plain use. The obligations attach to distributing or serving
  a modified version, not to running one.
- Output is yours. Run records, ledgers, evidence bundles and anything a governed mission produces
  carry no license claim from this project.

## When to talk to us instead

Buy a commercial license if you want to embed SPLAT in a product you ship closed, or offer it as a
service, without publishing your own source. That is the whole product: the same code, under terms
that do not propagate.

Typical fits:

- **Platform and OEM builders** putting kernel-enforced containment under someone else's agents,
  where the surrounding product stays proprietary.
- **Vendors** shipping SPLAT inside an appliance, an IDE, a runtime or an orchestrator.
- **Organisations with a blanket AGPL policy** that need the same code on terms their legal team
  already accepts.

A commercial licence can also carry things the public project does not promise: a support
commitment, a security contact with a response time, and a say in the roadmap.

**Contact:** plattenindustries@gmail.com — say what you are building and how it would be delivered.

## Contributions

Contributions are welcome and are accepted under the AGPL. Because the project offers commercial
licences, a contribution that arrives with no agreement in place would make that offer
unenforceable for the part you wrote — so anything beyond a trivial fix needs a signed contributor
agreement first. Open the pull request; that conversation happens before it merges, not after.

## What this license does not do

It does not make the security claims true. Those are held by the evidence files this repository
binds its README to, and by the tests that fail when the two disagree. A license is a grant of
rights, not a warranty: the AGPL disclaims every warranty, and so does this page.
