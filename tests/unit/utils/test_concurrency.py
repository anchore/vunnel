"""Tests for concurrency utilities."""

from __future__ import annotations

from unittest.mock import patch
import pytest

from vunnel.utils.concurrency import resolve_workers

class TestResolveWorkers:
    def test_integer_value(self):
        """Test that integer values are passed through."""
        assert resolve_workers(10) == 10
        assert resolve_workers(1) == 1
        assert resolve_workers(100) == 100

    def test_string_value(self):
        assert resolve_workers("8") == 8

    def test_auto_string(self):
        """Test that 'auto' string triggers calculation."""
        with patch("os.process_cpu_count", return_value=8):
            assert resolve_workers("auto") == 8

    def test_auto_case_insensitive(self):
        """Test that 'auto' is case-insensitive."""
        with patch("os.process_cpu_count", return_value=16):
            assert resolve_workers("AUTO") == 16
            assert resolve_workers("Auto") == 16
            assert resolve_workers("AuTo") == 16

    def test_invalid_string(self):
        """Test that invalid strings return default."""
        invalid_inputs = ["invalid", "*", ""]
        for invalid in invalid_inputs:
            with pytest.raises(ValueError):
                resolve_workers(invalid)

    def test_fallbacks(self):
        with patch("os.process_cpu_count", return_value=10):
            assert resolve_workers("auto") == 10
        with patch("os.process_cpu_count", return_value=None), patch("os.cpu_count", return_value=16):
            assert resolve_workers("auto") == 16
        with patch("os.process_cpu_count", return_value=None), patch("os.cpu_count", return_value=None):
            assert resolve_workers("auto") == 4
