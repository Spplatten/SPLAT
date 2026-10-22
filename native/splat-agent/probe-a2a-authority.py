#!/usr/bin/env python3
"""Published A2A delegation and public RARE sensors under an artifact-bound temporary daemon."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

spec = importlib.util.spec_from_file_location('agent_proof', Path(__file__).with_name('probe-agent-manifest.py'))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class AuthorityProof(agent.AgentProof):
    synthetic_only = False
    external_network_used = False

    def run(self):
        super().run()
        environment = dict(os.environ)
        values = {
            'SPLAT_AGENT_TOKEN': (self.root / 'token').read_text().strip(),
            'SPLAT_A2A_PROOF_EXE': agent.windows_path(self.args.mcp_exe.resolve()),
            'SPLAT_A2A_TEMPORARY_DAEMON_PID': str(self.process.pid),
            'SPLAT_A2A_PROOF_DIRECTORY': agent.windows_path(self.artifacts),
        }
        environment.update(values)
        environment['WSLENV'] = ':'.join(filter(None, [environment.get('WSLENV'), *(key + '/w' for key in values)]))
        # Consent for model calls is never inherited by a public-sensor containment proof.
        for key in ('SPLAT_ALLOW_ANTHROPIC_TEST_REQUESTS', 'SPLAT_ALLOW_HOST_TELEMETRY_TO_ANTHROPIC', 'SPLAT_RECORD_CORPUS'):
            environment.pop(key, None)
        self.external_network_used = None  # Unknown until the test's local observations are available.
        result = subprocess.run([str(self.args.dotnet), 'test', agent.windows_path(self.args.test_project.resolve()),
            '-c', 'Debug', '--no-build', '--filter',
            'FullyQualifiedName~TwoPublishedAgentsNarrowAuthorityAndRareSensorsRunUnderSignedLeases',
            '--logger', 'trx;LogFileName=a2a-authority-live.trx'], env=environment,
            capture_output=True, text=True, timeout=900)
        (self.artifacts / 'authority-test.stdout.txt').write_text(result.stdout)
        (self.artifacts / 'authority-test.stderr.txt').write_text(result.stderr)
        evidence = json.loads((self.artifacts / 'a2a-authority-proof.json').read_text())
        self.external_network_used = evidence['observations'].get('externalNetworkAttempted', False)
        for name, passed in evidence['checks'].items():
            self.check('authority_' + name, passed)
        self.check('published_authority_live_test_passed', result.returncode == 0)
        self.observations['authorityEvidence'] = str(self.artifacts / 'a2a-authority-proof.json')
        self.observations['externalDestinations'] = ['itunes.apple.com:443', 'apps.apple.com:443']
        self.observations['modelApiRequests'] = 0


def configure(parser):
    agent.configure(parser)
    parser.add_argument('--dotnet', required=True, type=Path)
    parser.add_argument('--test-project', required=True, type=Path)


if __name__ == '__main__':
    raise SystemExit(agent.runner.main(AuthorityProof, __file__, configure))
