# Commercial licensing

SPLAT is published under the **GNU Affero General Public License v3.0** ([LICENSE](LICENSE)).
Copyright © 2026 Platten Industries LLC. All rights reserved where not granted by that license.

The AGPL is a deliberate choice rather than a default. Read it before you build on this.

## What the AGPL gives you, free

Everything, if you are willing to be bound by it: run it, read it, change it, ship it, embed it.
The published core has no evaluation period, no seat count, and no telemetry. The daemon in
`native/splat-agent` is the whole thing, not a crippled edition of it.

Separately supplied Corporate extensions are outside this Community source grant and require their
own commercial agreement. Their availability does not restrict the AGPL rights already granted
for the published core. Third-party components keep their own licenses.

## What it asks in return

The full license in `LICENSE` governs; this page is a summary.

- **Conveying copies:** retain the required notices and license. Conveying covered binaries,
  whether modified or unmodified, requires Corresponding Source through a method permitted by
  AGPL section 6. Corresponding Source includes the applicable build/install scripts and required
  non-system dependencies; an unrelated source snapshot is insufficient.
- **Modified network-interactive versions:** section 13 requires a prominent offer of the version's
  Corresponding Source to all users interacting with it remotely through a computer network.
  Provide access at no charge as the license specifies. Do not assume a blanket exemption merely
  because a deployment is called internal.
- **Ordinary execution:** receiving or running a copy does not require accepting an additional
  SPLAT EULA. Business use alone does not require buying a commercial license.

The AGPL does not require you to submit changes to Platten Industries or automatically disclose
every independent application or workload that communicates with SPLAT. Whether components form a
covered combined work depends on their relationship. Source must be offered to the recipients/users
the license identifies; this is not a blanket obligation to publish all company source.

Run records, ledgers, evidence bundles and independent mission outputs carry no license claim from
SPLAT merely because SPLAT produced them. Embedded third-party material retains its own rights.

## When to talk to us instead

A separately executed commercial agreement can grant alternative permissions for SPLAT code that
Platten Industries LLC owns or has authority to relicense. Discuss that option when a proposed combined
or derivative product cannot comply with the AGPL, or your procurement policy excludes AGPL software.
A commercial agreement does not relicense third-party dependencies or remove their obligations.
Selling a service or keeping an independent surrounding product proprietary does not, by itself,
determine that a commercial SPLAT license is required.

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

Contributions follow `CONTRIBUTING.md` and the contributor agreement in `CLA.md`. Commercial
relicensing requires the necessary rights in each included contribution; the presence of a CLA
template does not prove that a contributor signed it. A contribution policy does not restrict
anyone's existing right to modify or distribute the Community edition under the AGPL.

## What this license does not do

It does not make the security claims true. Those are held by the evidence files this repository
binds its README to, and by the tests that fail when the two disagree. A license is a grant of
rights, not a warranty: the AGPL disclaims every warranty, and so does this page.
