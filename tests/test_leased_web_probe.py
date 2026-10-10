"""Offline tests for the exact Python resource embedded in the eight leased sensors."""
import ast
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / "src/MissionController.Infrastructure.Data/Catalog/LeasedWebProbe.py"


def library():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    # Load the real functions without its CLI entry point: these tests must never contact a source.
    if not isinstance(tree.body[-1], ast.Try):
        raise AssertionError("Probe entry point changed; review the offline loader")
    tree.body.pop()
    scope = dict(BASE="https://publisher.example/", MODE="index", PINS=["192.0.2.7"], PARAMS={})
    exec(compile(tree, str(SOURCE), "exec"), scope)
    return scope


class LeasedWebProbeTests(unittest.TestCase):
    def setUp(self):
        self.code = library()

    def test_numeric_destination_preserves_tls_hostname(self):
        connection = self.code["PinnedConnection"]("publisher.example", timeout=45)
        raw, tls = Mock(), Mock()
        connection._context = tls
        with patch.object(self.code["socket"], "socket", return_value=raw):
            connection.connect()
        raw.connect.assert_called_once_with(("192.0.2.7", 443))
        tls.wrap_socket.assert_called_once_with(raw, server_hostname="publisher.example")
        self.assertIs(connection.sock, tls.wrap_socket.return_value)

    def test_failed_pin_is_closed_before_trying_the_next_compiled_pin(self):
        self.code["PINS"] = ["192.0.2.7", "192.0.2.8"]
        connection = self.code["PinnedConnection"]("publisher.example", timeout=45)
        first, second = Mock(), Mock()
        first.connect.side_effect = OSError("unavailable")
        connection._context = Mock()
        with patch.object(self.code["socket"], "socket", side_effect=[first, second]):
            connection.connect()
        first.close.assert_called_once()
        second.connect.assert_called_once_with(("192.0.2.8", 443))

    def response(self, status, data):
        response = Mock(status=status)
        response.read.return_value = data
        response.getheader.return_value = "application/json"
        connection = Mock()
        connection.getresponse.return_value = response
        self.code["PinnedConnection"] = Mock(return_value=connection)
        return connection, response

    def test_redirect_is_refused_without_following_location(self):
        connection, _ = self.response(302, b"")
        with self.assertRaisesRegex(ValueError, "redirect refused"):
            self.code["fetch"]("data.json")
        connection.request.assert_called_once()
        connection.close.assert_called_once()

    def test_response_is_bounded_and_connection_is_closed(self):
        self.code["MAX_BODY"] = 8
        connection, response = self.response(200, b"123456789")
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.code["fetch"]("data.json")
        response.read.assert_called_once_with(9)
        connection.close.assert_called_once()

    def bls_output(self, rows):
        document = dict(status="REQUEST_SUCCEEDED", Results=dict(series=[dict(seriesID="fixture", data=rows)]))
        self.code["PARAMS"] = dict(SeriesId="fixture", StartYear="2024", EndYear="2026")
        self.code["fetch"] = lambda *args: (200, "application/json", json.dumps(document).encode())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.code["probe"]()
        return output.getvalue()

    def test_year_change_uses_matching_month_and_excludes_annual_average(self):
        rows = [dict(year="2026", period="M13", periodName="Annual", value="999"),
                dict(year="2026", period="M09", periodName="September", value="110"),
                dict(year="2025", period="M10", periodName="October", value="80"),
                dict(year="2025", period="M09", periodName="September", value="100")]
        output = self.bls_output(rows)
        self.assertIn("LATEST_PERIOD: September 2026", output)
        self.assertIn("TWELVE_MONTH_CHANGE_PCT: 10.0", output)
        self.assertNotIn("999", output)

    def test_missing_prior_year_is_unavailable_instead_of_a_fabricated_change(self):
        output = self.bls_output([dict(year="2026", period="M09", periodName="September", value="110")])
        self.assertIn("TWELVE_MONTH_CHANGE_PCT: UNAVAILABLE", output)


if __name__ == "__main__":
    unittest.main()
