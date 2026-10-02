@{
    # Palette. Dark enough that a terminal replay cut against a card does not flash the viewer.
    Background = '0x0B0E14'
    Headline   = '0xE8EDF4'
    Accent     = '0x7FB3FF'
    Muted      = '0x8A94A6'

    # The order of the final cut. Each id resolves to demo\cards\<id>.mp4 if this file declares a
    # card for it or a -Terminal run rendered it, otherwise to demo\raw\<id>.mp4 from a -Capture.
    # Ids that resolve to neither are reported by -Assemble rather than silently dropped, because a
    # tape missing its proof act must not quietly become a slideshow.
    #
    # Footage leads. The first thing on screen is the kernel refusing a command, before any claim
    # about what that means - an earlier cut opened with five cards of argument and was, correctly,
    # called a slide deck. The cards that survive are the ones that caption something the viewer
    # has already seen.
    Sequence = @(
        '01-hook',      # terminal replay: the recorded last-hop probe
        '02-title',
        '03-problem',
        '04-lease',
        '05-doctor',    # terminal replay: this host, live
        '06-console',   # CAPTURE: the console running a mission
        '07-drift',     # CAPTURE: edit a claim, watch the suite refuse it
        '08-install',
        '09-limits',
        '10-close'
    )

    Cards = @(
        @{
            Id = '02-title'; Seconds = 10
            Lines = @(
                @{ Text = 'Agents don''t get trust.'; Size = 104; Color = 'Headline' }
                @{ Text = 'They get a lease.';        Size = 104; Color = 'Accent' }
                @{ Text = '';                         Size = 40;  Color = 'Muted' }
                @{ Text = 'SPLAT — Sandboxed Process Lease & Agent Telemetry'; Size = 34; Color = 'Muted' }
            )
        },
        @{
            Id = '03-problem'; Seconds = 12
            Lines = @(
                @{ Text = 'Prompt rules, regex guards and wrapper APIs all run'; Size = 50; Color = 'Muted' }
                @{ Text = 'beside the agent, at the agent''s own privilege.';    Size = 50; Color = 'Muted' }
                @{ Text = '';                                                    Size = 40; Color = 'Muted' }
                @{ Text = 'A hijacked agent routes around a guard';  Size = 68; Color = 'Headline' }
                @{ Text = 'it shares privilege with.';               Size = 68; Color = 'Accent' }
                @{ Text = '';                                        Size = 36; Color = 'Muted' }
                @{ Text = 'So the boundary goes below the agent, where it cannot reach.'; Size = 38; Color = 'Muted' }
            )
        },
        @{
            Id = '04-lease'; Seconds = 13
            Lines = @(
                @{ Text = 'A lease names'; Size = 52; Color = 'Muted' }
                @{ Text = 'this binary, this destination, this many seconds.'; Size = 60; Color = 'Headline' }
                @{ Text = '';              Size = 40; Color = 'Muted' }
                @{ Text = 'An exec or a connect() outside it returns -EPERM from the kernel —'; Size = 40; Color = 'Accent' }
                @{ Text = 'not from a wrapper the agent shares privilege with.'; Size = 40; Color = 'Muted' }
                @{ Text = '';              Size = 32; Color = 'Muted' }
                @{ Text = 'A container''s unit is a machine. A lease''s unit is one task.'; Size = 36; Color = 'Muted' }
            )
        },
        @{
            Id = '08-install'; Seconds = 15
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
            Id = '09-limits'; Seconds = 20
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
            Id = '10-close'; Seconds = 13
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
