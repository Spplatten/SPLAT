@{
    # Palette. Dark enough that a terminal capture cut against a card does not flash the viewer.
    Background = '0x0B0E14'
    Headline   = '0xE8EDF4'
    Accent     = '0x7FB3FF'
    Muted      = '0x8A94A6'

    # The order of the final cut. Each id resolves to demo\cards\<id>.mp4 if this file declares a
    # card for it, otherwise to demo\raw\<id>.mp4 from a -Capture run. Ids that resolve to neither
    # are reported by -Assemble rather than silently dropped, because a tape missing its proof act
    # must not quietly become a slideshow.
    Sequence = @(
        '00-open',
        '01-beside',
        '02-around',
        '03-below',
        '04-lease',
        '05-unit',
        '06-policy',
        '07-reprove',
        '08-console',
        '09-install',
        '10-limits',
        '11-close'
    )

    Cards = @(
        @{
            Id = '00-open'; Seconds = 12
            Lines = @(
                @{ Text = 'Agents don''t get trust.'; Size = 104; Color = 'Headline' }
                @{ Text = 'They get a lease.';        Size = 104; Color = 'Accent' }
                @{ Text = '';                         Size = 40;  Color = 'Muted' }
                @{ Text = 'SPLAT — Sandboxed Process Lease & Agent Telemetry'; Size = 34; Color = 'Muted' }
            )
        },
        @{
            Id = '01-beside'; Seconds = 10
            Lines = @(
                @{ Text = 'Prompt rules. Regex guards. Wrapper APIs.'; Size = 56; Color = 'Muted' }
                @{ Text = '';                                          Size = 28; Color = 'Muted' }
                @{ Text = 'All of it runs beside the agent,';           Size = 72; Color = 'Headline' }
                @{ Text = 'at the agent''s own privilege.';             Size = 72; Color = 'Accent' }
            )
        },
        @{
            Id = '02-around'; Seconds = 11
            Lines = @(
                @{ Text = 'A hijacked agent routes around a guard';  Size = 68; Color = 'Headline' }
                @{ Text = 'it shares privilege with.';               Size = 68; Color = 'Headline' }
                @{ Text = '';                                        Size = 36; Color = 'Muted' }
                @{ Text = 'Prompt injection is not a bug with a patch. It is what'; Size = 36; Color = 'Muted' }
                @{ Text = 'happens when untrusted text and instructions share a channel.'; Size = 36; Color = 'Muted' }
            )
        },
        @{
            Id = '03-below'; Seconds = 9
            Lines = @(
                @{ Text = 'So the boundary goes below the agent.'; Size = 68; Color = 'Headline' }
                @{ Text = '';                                      Size = 32; Color = 'Muted' }
                @{ Text = 'In the kernel, where the agent cannot reach it.'; Size = 52; Color = 'Accent' }
            )
        },
        @{
            Id = '04-lease'; Seconds = 14
            Lines = @(
                @{ Text = 'A lease names'; Size = 56; Color = 'Muted' }
                @{ Text = 'this binary, this destination, this many seconds.'; Size = 60; Color = 'Headline' }
                @{ Text = '';              Size = 40; Color = 'Muted' }
                @{ Text = 'An exec or a connect() outside it returns -EPERM from the kernel —'; Size = 40; Color = 'Accent' }
                @{ Text = 'not from a wrapper the agent shares privilege with.'; Size = 40; Color = 'Muted' }
            )
        },
        @{
            Id = '05-unit'; Seconds = 11
            Lines = @(
                @{ Text = 'A container''s unit is a machine.'; Size = 64; Color = 'Muted' }
                @{ Text = 'A lease''s unit is one task.';       Size = 64; Color = 'Headline' }
                @{ Text = '';                                   Size = 36; Color = 'Muted' }
                @{ Text = 'docker run hands the workload a box. A lease hands it a sentence.'; Size = 36; Color = 'Accent' }
            )
        },
        @{
            Id = '09-install'; Seconds = 16
            Lines = @(
                @{ Text = 'One stanza in an MCP client''s config.'; Size = 60; Color = 'Headline' }
                @{ Text = '';                                        Size = 32; Color = 'Muted' }
                @{ Text = 'Met on a second machine on 2026-09-18: Windows 11 Home, stock WSL'; Size = 34; Color = 'Muted' }
                @{ Text = 'kernel, no toolchain. It provisioned itself to enforcing, passed the'; Size = 34; Color = 'Muted' }
                @{ Text = 'same probe, and survived a restart.'; Size = 34; Color = 'Muted' }
                @{ Text = '';                                    Size = 28; Color = 'Muted' }
                @{ Text = 'That run found two defects this machine never showed.'; Size = 34; Color = 'Accent' }
            )
        },
        @{
            Id = '10-limits'; Seconds = 22
            Lines = @(
                @{ Text = 'What this does not establish'; Size = 60; Color = 'Accent' }
                @{ Text = '';                             Size = 40; Color = 'Muted' }
                @{ Text = 'One engineer. No second reviewer has read this code,'; Size = 38; Color = 'Headline' }
                @{ Text = 'and no auditor has assessed it.'; Size = 38; Color = 'Headline' }
                @{ Text = 'Caller identity on the bridge trusts a secret, not the peer.'; Size = 38; Color = 'Headline' }
                @{ Text = 'Scratch-specific execution authorization: open.'; Size = 38; Color = 'Headline' }
                @{ Text = 'The live test corpus is incomplete, and the badge says so.'; Size = 38; Color = 'Headline' }
                @{ Text = '';                             Size = 30; Color = 'Muted' }
                @{ Text = 'Claims in this repository have been withdrawn after passing once.'; Size = 38; Color = 'Muted' }
            )
        },
        @{
            Id = '11-close'; Seconds = 14
            Lines = @(
                @{ Text = 'Every claim is bound to a probe you can run on your own host.'; Size = 46; Color = 'Headline' }
                @{ Text = 'The build fails when the prose and the evidence disagree.'; Size = 46; Color = 'Accent' }
                @{ Text = '';                                                           Size = 56; Color = 'Muted' }
                @{ Text = 'github.com/Spplatten/SPLAT'; Size = 38; Color = 'Muted' }
                @{ Text = 'AGPL-3.0 · Platten Industries'; Size = 32; Color = 'Muted' }
            )
        }
    )
}
