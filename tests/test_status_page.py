"""Tests for the status-page table reader behind --info.

The reader replaced a regex over tag-stripped HTML, which matched by luck of
whitespace and could pick up unrelated text. These lock in the structural
behaviour, including the cases that made the old approach wrong.
"""

import pytest

from zte_unlock.factory_mode import _parse_status_fields

SIMPLE = """<html><body><table>
<tr><td>Device Type</td><td>F670LV9.0</td></tr>
<tr><td>Hardware Version</td><td>V9.0</td></tr>
<tr><td>Software Version</td><td>V9.0.11P1N40</td></tr>
<tr><td>Boot Version</td><td>V9.0.11P10N1</td></tr>
</table></body></html>"""


class TestBasicParsing:
    def test_reads_a_simple_table(self):
        fields = _parse_status_fields(SIMPLE)

        assert fields["device type"] == "F670LV9.0"
        assert fields["software version"] == "V9.0.11P1N40"
        assert fields["boot version"] == "V9.0.11P10N1"

    def test_labels_are_lowercased_and_values_are_kept_verbatim(self):
        fields = _parse_status_fields(SIMPLE)

        assert all(k == k.lower() for k in fields)
        assert fields["software version"] == "V9.0.11P1N40"  # the V is kept

    def test_empty_page_yields_nothing(self):
        assert _parse_status_fields("") == {}
        assert _parse_status_fields("<html><body>nothing here</body></html>") == {}


class TestStructureOverText:
    def test_ignores_mentioning_a_version_outside_the_table(self):
        """The case the regex-over-text approach got wrong.

        A version mentioned in a footer must not shadow the real table value.
        """
        page = """<html><body>
        <table><tr><td>Software Version</td><td>V9.0.11P1N40</td></tr></table>
        <p>Note: this firmware differs from Software Version 9.9.9 upstream</p>
        </body></html>"""

        fields = _parse_status_fields(page)

        assert fields["software version"] == "V9.0.11P1N40"
        assert "9.9.9" not in fields["software version"]

    def test_survives_attributes_on_every_cell(self):
        page = """<table><tr>
        <td class="a" id="b">Software Version</td>
        <td data-x="1" data-y="2">V9.0.11P1N40</td>
        </tr></table>"""

        assert _parse_status_fields(page)["software version"] == "V9.0.11P1N40"

    def test_ignores_rows_that_are_not_label_value_pairs(self):
        page = """<table>
        <tr><td colspan="3">Header row</td></tr>
        <tr><td>Device Type</td><td>F670LV9.0</td></tr>
        </table>"""

        fields = _parse_status_fields(page)

        assert fields == {"device type": "F670LV9.0"}

    def test_tolerates_malformed_html_without_raising(self):
        """Must never crash the diagnostic path."""
        page = "<table><tr><td>Software Version<td>V9.0.11P1N40</table><<<>>>"

        # Whatever it recovers, it must not raise.
        assert isinstance(_parse_status_fields(page), dict)


class TestHeaderCells:
    def test_reads_th_cells_as_labels(self):
        page = "<table><tr><th>Software Version</th><th>V9.0.11P1N40</th></tr></table>"

        assert _parse_status_fields(page)["software version"] == "V9.0.11P1N40"