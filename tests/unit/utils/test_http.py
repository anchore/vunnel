from __future__ import annotations

import logging
import pytest
import requests
from unittest.mock import patch, MagicMock, call
from vunnel.utils import http


class TestGetRequests:
    @pytest.fixture()
    def mock_logger(self):
        logger = logging.getLogger("test-http-utils")
        return MagicMock(logger, autospec=True)

    @pytest.fixture()
    def error_response(self):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("HTTP ERROR")
        return mock_response

    @pytest.fixture()
    def success_response(self):
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.raise_for_status.side_effect = None
        response.status_code = 200
        return response

    @patch("time.sleep")
    @patch("requests.get")
    def test_raises_when_out_of_retries(self, mock_requests, mock_sleep, mock_logger, error_response):
        mock_requests.side_effect = [Exception("could not attempt request"), error_response, error_response]
        with pytest.raises(requests.HTTPError):
            http.get("http://example.com/some-path", mock_logger, retries=2, backoff_in_seconds=3)
        mock_logger.error.assert_called()

    @patch("time.sleep")
    @patch("requests.get")
    def test_succeeds_if_retries_succeed(self, mock_requests, mock_sleep, mock_logger, error_response, success_response):
        mock_requests.side_effect = [error_response, success_response]
        http.get("http://example.com/some-path", mock_logger, retries=1, backoff_in_seconds=22)
        mock_sleep.assert_called_with(22)
        mock_logger.warning.assert_called()
        mock_logger.error.assert_not_called()
        mock_requests.assert_called_with("http://example.com/some-path", timeout=http.DEFAULT_TIMEOUT)

    @patch("requests.get")
    def test_timeout_is_passed_in(self, mock_requests, mock_logger):
        http.get("http://example.com/some-path", mock_logger, timeout=12345)
        mock_requests.assert_called_with("http://example.com/some-path", timeout=12345)

    @patch("time.sleep")
    @patch("requests.get")
    def test_sleeps_right_amount_between_retries(self, mock_requests, mock_sleep, mock_logger, error_response, success_response):
        mock_requests.side_effect = [error_response, error_response, error_response, success_response]
        http.get("http://example.com/some-path", mock_logger, backoff_in_seconds=123, retries=3)
        assert mock_sleep.call_args_list == [call(123), call(123), call(123)]

    @patch("time.sleep")
    @patch("requests.get")
    def test_it_logs_the_url_on_failure(self, mock_requests, mock_sleep, mock_logger, error_response):
        mock_requests.side_effect = [error_response, error_response, error_response]
        url = "http://example.com/some-path"
        with pytest.raises(requests.HTTPError):
            http.get(url, mock_logger, retries=2)

        assert url in mock_logger.error.call_args.args[0]

    @patch("time.sleep")
    @patch("requests.get")
    def test_it_log_warns_errors(self, mock_requests, mock_sleep, mock_logger, error_response, success_response):
        mock_requests.side_effect = [error_response, success_response]
        http.get("http://example.com/some-path", mock_logger, retries=1, backoff_in_seconds=33)
        assert "HTTP ERROR" in mock_logger.warning.call_args.args[0]
        assert "will retry in 33 seconds" in mock_logger.warning.call_args.args[0]
