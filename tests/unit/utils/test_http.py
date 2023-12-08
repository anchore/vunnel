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
    def test_correct_number_of_retria(self, mock_requests, mock_sleep, mock_logger, error_response):
        mock_requests.side_effect = [
            error_response,
            error_response,
            error_response,
            error_response,
            error_response,
        ]  # more than enough
        with pytest.raises(requests.HTTPError):
            http.get("http://example.com/some-path", mock_logger, retries=2, backoff_in_seconds=3)
        assert len(mock_requests.call_args_list) == 3  # once for initial plus two retries

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
    @patch("random.uniform")
    def test_exponential_backoff_and_jitter(
        self, mock_uniform_random, mock_requests, mock_sleep, mock_logger, error_response, success_response
    ):
        mock_requests.side_effect = [error_response, error_response, error_response, success_response]
        mock_uniform_random.side_effect = [0.5, 0.4, 0.1]
        http.get("http://example.com/some-path", mock_logger, backoff_in_seconds=10, retries=3)
        assert mock_sleep.call_args_list == [call(10), call(10 * 2 + 0.5), call(10 * 4 + 0.4)]

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

    @patch("time.sleep")
    @patch("requests.get")
    def test_it_calls_status_handler(self, mock_requests, mock_sleep, mock_logger, error_response, success_response):
        mock_requests.side_effect = [error_response]
        status_handler = MagicMock()
        result = http.get(
            "http://example.com/some-path", mock_logger, status_handler=status_handler, retries=1, backoff_in_seconds=33
        )
        mock_sleep.assert_not_called()
        status_handler.assert_called_once()
        assert status_handler.call_args.args[0] == error_response
        assert result == error_response

    @patch("time.sleep")
    @patch("requests.get")
    def test_it_retries_when_status_handler_raises(
        self, mock_requests, mock_sleep, mock_logger, error_response, success_response
    ):
        mock_requests.side_effect = [success_response, error_response]
        status_handler = MagicMock()
        status_handler.side_effect = [Exception("custom exception"), None]
        result = http.get(
            "http://example.com/some-path", mock_logger, status_handler=status_handler, retries=1, backoff_in_seconds=33
        )
        mock_sleep.assert_called_with(33)
        # custom status handler raised the first time it was called,
        # so we expect the second mock response to be returned overall
        assert result == error_response
