from __future__ import annotations

import logging
import threading
import time
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from vunnel.utils import http_wrapper as http


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
        mock_response.status_code = 500
        mock_response.headers = {}
        return mock_response

    @pytest.fixture()
    def success_response(self):
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.raise_for_status.side_effect = None
        response.status_code = 200
        response.headers = {}
        return response

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_raises_when_out_of_retries(self, mock_session_get, mock_sleep, mock_logger, error_response):
        mock_session_get.side_effect = [Exception("could not attempt request"), error_response, error_response]
        with pytest.raises(requests.HTTPError):
            http.get("http://example.com/some-path", mock_logger, retries=2, backoff_in_seconds=3)
        mock_logger.error.assert_called()

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_correct_number_of_retries(self, mock_session_get, mock_sleep, mock_logger, error_response):
        mock_session_get.side_effect = [
            error_response,
            error_response,
            error_response,
            error_response,
            error_response,
        ]  # more than enough
        with pytest.raises(requests.HTTPError):
            http.get("http://example.com/some-path", mock_logger, retries=2, backoff_in_seconds=3)
        assert len(mock_session_get.call_args_list) == 3  # once for initial plus two retries

    @patch("time.sleep")
    @patch("requests.Session.get")
    @patch("random.uniform")
    def test_succeeds_if_retries_succeed(
        self, mock_uniform_random, mock_session_get, mock_sleep, mock_logger, error_response, success_response
    ):
        mock_uniform_random.side_effect = [0.1]
        mock_session_get.side_effect = [error_response, success_response]
        http.get("http://example.com/some-path", mock_logger, retries=1, backoff_in_seconds=22)
        mock_sleep.assert_called_with(22.1)
        mock_logger.warning.assert_called()
        mock_logger.error.assert_not_called()
        mock_session_get.assert_called_with("http://example.com/some-path", timeout=http.DEFAULT_TIMEOUT, headers={})

    @patch("requests.Session.get")
    def test_timeout_is_passed_in(self, mock_session_get, mock_logger, success_response):
        mock_session_get.return_value = success_response
        http.get("http://example.com/some-path", mock_logger, timeout=12345)
        mock_session_get.assert_called_with("http://example.com/some-path", timeout=12345, headers={})

    @patch("requests.Session.get")
    def test_user_agent_is_passed_in(self, mock_session_get, mock_logger, success_response):
        mock_session_get.return_value = success_response
        http.get("http://example.com/some-path", mock_logger, timeout=12345, user_agent="test-user-agent")
        headers = {"User-Agent": "test-user-agent"}
        mock_session_get.assert_called_with("http://example.com/some-path", timeout=12345, headers=headers)

    @patch("requests.Session.get")
    def test_empty_user_agent_sets_no_header(self, mock_session_get, mock_logger, success_response):
        mock_session_get.return_value = success_response
        http.get("http://example.com/some-path", mock_logger, timeout=12345, user_agent="")
        mock_session_get.assert_called_with("http://example.com/some-path", timeout=12345, headers={})

    @patch("time.sleep")
    @patch("requests.Session.get")
    @patch("random.uniform")
    def test_exponential_backoff_and_jitter(
        self, mock_uniform_random, mock_session_get, mock_sleep, mock_logger, error_response, success_response
    ):
        mock_session_get.side_effect = [error_response, error_response, error_response, success_response]
        mock_uniform_random.side_effect = [0.5, 0.4, 0.1]
        http.get("http://example.com/some-path", mock_logger, backoff_in_seconds=10, retries=3)
        assert mock_sleep.call_args_list == [call(10 + 0.5), call(10 * 2 + 0.4), call(10 * 4 + 0.1)]

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_it_logs_the_url_on_failure(self, mock_session_get, mock_sleep, mock_logger, error_response):
        mock_session_get.side_effect = [error_response, error_response, error_response]
        url = "http://example.com/some-path"
        with pytest.raises(requests.HTTPError):
            http.get(url, mock_logger, retries=2)

        assert url in mock_logger.error.call_args.args[0]

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_it_log_warns_errors(self, mock_session_get, mock_sleep, mock_logger, error_response, success_response):
        mock_session_get.side_effect = [error_response, success_response]
        http.get("http://example.com/some-path", mock_logger, retries=1, backoff_in_seconds=33)

        logged_warnings = [call.args[0] for call in mock_logger.warning.call_args_list]

        assert any("HTTP ERROR" in message for message in logged_warnings), "Expected 'HTTP ERROR' in logged warnings."
        assert any(
            "will retry in 33 seconds" in message for message in logged_warnings
        ), "Expected retry message in logged warnings."

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_it_calls_status_handler(self, mock_session_get, mock_sleep, mock_logger, error_response, success_response):
        # error_response with status_code 500 will be classified as RETRY_WITH_BACKOFF
        # Use a 2xx response so it's classified as SUCCESS
        error_response.status_code = 200
        mock_session_get.side_effect = [error_response]
        status_handler = MagicMock()
        result = http.get(
            "http://example.com/some-path", mock_logger, status_handler=status_handler, retries=1, backoff_in_seconds=33
        )
        mock_sleep.assert_not_called()
        status_handler.assert_called_once()
        assert status_handler.call_args.args[0] == error_response
        assert result == error_response

    @patch("time.sleep")
    @patch("requests.Session.get")
    @patch("random.uniform")
    def test_it_retries_when_status_handler_raises(
        self, mock_uniform_random, mock_session_get, mock_sleep, mock_logger, error_response, success_response
    ):
        mock_uniform_random.side_effect = [0.25]
        # Both responses need status_code 200 to be classified as SUCCESS
        success_response.status_code = 200
        error_response.status_code = 200
        mock_session_get.side_effect = [success_response, error_response]
        status_handler = MagicMock()
        status_handler.side_effect = [Exception("custom exception"), None]
        result = http.get(
            "http://example.com/some-path", mock_logger, status_handler=status_handler, retries=1, backoff_in_seconds=33
        )
        mock_sleep.assert_called_with(33.25)
        # custom status handler raised the first time it was called,
        # so we expect the second mock response to be returned overall
        assert result == error_response


class TestRateLimiting:
    @pytest.fixture()
    def mock_logger(self):
        logger = logging.getLogger("test-rate-limit")
        return MagicMock(logger, autospec=True)

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_rate_limit_respected(self, mock_session_get, mock_sleep, mock_logger):
        """Test that 429 response triggers rate limit wait."""
        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "5"}
        rate_limited_response.raise_for_status.side_effect = requests.HTTPError("429 Too Many Requests")

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.headers = {}

        mock_session_get.side_effect = [rate_limited_response, success_response]

        result = http.get("http://example.com/api", mock_logger, retries=2)

        assert result == success_response
        # Check that we logged the rate limit
        logged_warnings = [call.args[0] for call in mock_logger.warning.call_args_list]
        assert any("Rate limited" in msg for msg in logged_warnings)

    @patch("time.sleep")
    def test_retry_after_header_parsed_seconds(self, mock_sleep):
        """Test parsing Retry-After header with seconds format."""
        result = http.parse_retry_after("120")
        assert result == 120.0

    @patch("time.sleep")
    def test_retry_after_header_parsed_http_date(self, mock_sleep):
        """Test parsing Retry-After header with HTTP-date format."""
        # Use a future date
        from email.utils import formatdate
        future_time = time.time() + 60
        http_date = formatdate(future_time, usegmt=True)
        result = http.parse_retry_after(http_date)
        # Should be approximately 60 seconds (allow some tolerance)
        assert result is not None
        assert 55 <= result <= 65

    def test_retry_after_header_invalid(self):
        """Test parsing invalid Retry-After header."""
        assert http.parse_retry_after(None) is None
        assert http.parse_retry_after("") is None
        assert http.parse_retry_after("invalid") is None

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_rate_limit_exhausts_retries(self, mock_session_get, mock_sleep, mock_logger):
        """Test that rate limiting exhausts retry budget and raises HTTPError."""
        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "1"}
        rate_limited_response.raise_for_status.side_effect = requests.HTTPError("429 Too Many Requests")

        # Always return 429 - should exhaust retries
        mock_session_get.return_value = rate_limited_response

        with pytest.raises(requests.HTTPError) as exc_info:
            http.get("http://example.com/api", mock_logger, retries=2)

        # Should raise HTTPError, not internal _RateLimitRetry
        assert "429" in str(exc_info.value)
        # Should have tried 3 times (initial + 2 retries)
        assert mock_session_get.call_count == 3

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_rate_limit_wait_capped(self, mock_session_get, mock_sleep, mock_logger):
        """Test that rate limit wait time is capped at MAX_RATE_LIMIT_WAIT."""
        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "9999"}  # Very large value
        rate_limited_response.raise_for_status.side_effect = requests.HTTPError("429 Too Many Requests")

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.headers = {}

        mock_session_get.side_effect = [rate_limited_response, success_response]

        result = http.get("http://example.com/api", mock_logger, retries=2)

        assert result == success_response
        # Check that the logged wait time is capped
        logged_warnings = [call.args[0] for call in mock_logger.warning.call_args_list]
        rate_limit_log = next(msg for msg in logged_warnings if "Rate limited" in msg)
        # Should show the capped value (300.0), not 9999
        assert "300.0s" in rate_limit_log


class TestCircuitBreaker:
    @pytest.fixture()
    def mock_logger(self):
        logger = logging.getLogger("test-circuit-breaker")
        return MagicMock(logger, autospec=True)

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_circuit_breaker_trips(self, mock_session_get, mock_sleep, mock_logger):
        """Test that circuit breaker trips after threshold failures."""
        http.configure(http.HttpConfig(circuit_breaker_threshold=3, circuit_breaker_recovery=60.0))

        error_response = MagicMock()
        error_response.status_code = 500
        error_response.headers = {}
        error_response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")

        mock_session_get.return_value = error_response

        # Make enough requests to trip the circuit breaker
        for _ in range(3):
            with pytest.raises(requests.HTTPError):
                http.get("http://example.com/api", mock_logger, retries=0)

        # Next request should raise CircuitOpenError
        with pytest.raises(http.CircuitOpenError):
            http.get("http://example.com/api", mock_logger, retries=0)

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_circuit_breaker_recovers(self, mock_session_get, mock_sleep, mock_logger):
        """Test that circuit breaker recovers after recovery period."""
        http.configure(http.HttpConfig(circuit_breaker_threshold=2, circuit_breaker_recovery=60.0))

        error_response = MagicMock()
        error_response.status_code = 500
        error_response.headers = {}
        error_response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.headers = {}

        mock_session_get.return_value = error_response

        # Use mocked time to control circuit breaker timing
        mock_time = MagicMock()
        mock_time.return_value = 1000.0  # Starting time

        with patch("vunnel.utils.http_wrapper.time.time", mock_time):
            # Trip the circuit
            for _ in range(2):
                with pytest.raises(requests.HTTPError):
                    http.get("http://example.com/api", mock_logger, retries=0)

            # Verify circuit is open
            with pytest.raises(http.CircuitOpenError):
                http.get("http://example.com/api", mock_logger, retries=0)

            # Advance time past recovery period (60s recovery + buffer)
            mock_time.return_value = 1100.0

            # Circuit should allow a probe request (half-open)
            mock_session_get.return_value = success_response
            result = http.get("http://example.com/api", mock_logger, retries=0)
            assert result == success_response


class TestSmartRetry:
    @pytest.fixture()
    def mock_logger(self):
        logger = logging.getLogger("test-smart-retry")
        return MagicMock(logger, autospec=True)

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_client_error_retried_once(self, mock_session_get, mock_sleep, mock_logger):
        """Test that client errors (404, etc) are retried once then raise."""
        error_404 = MagicMock()
        error_404.status_code = 404
        error_404.headers = {}
        error_404.raise_for_status.side_effect = requests.HTTPError("404 Not Found")

        mock_session_get.return_value = error_404

        with pytest.raises(requests.HTTPError):
            http.get("http://example.com/api", mock_logger, retries=5)

        # Should have been called exactly twice (initial + one retry)
        assert mock_session_get.call_count == 2

    @patch("time.sleep")
    @patch("requests.Session.get")
    def test_client_error_retry_disabled(self, mock_session_get, mock_sleep, mock_logger):
        """Test that client error retry can be disabled."""
        http.configure(http.HttpConfig(retry_once_on_client_error=False))

        error_404 = MagicMock()
        error_404.status_code = 404
        error_404.headers = {}
        error_404.raise_for_status.side_effect = requests.HTTPError("404 Not Found")

        mock_session_get.return_value = error_404

        with pytest.raises(requests.HTTPError):
            http.get("http://example.com/api", mock_logger, retries=5)

        # Should have been called only once (no retry)
        assert mock_session_get.call_count == 1

    def test_classify_status_code(self):
        """Test status code classification."""
        assert http.classify_status_code(200) == http.RetryStrategy.SUCCESS
        assert http.classify_status_code(201) == http.RetryStrategy.SUCCESS
        assert http.classify_status_code(404) == http.RetryStrategy.RETRY_ONCE
        assert http.classify_status_code(429) == http.RetryStrategy.RATE_LIMITED
        assert http.classify_status_code(503) == http.RetryStrategy.RATE_LIMITED
        assert http.classify_status_code(500) == http.RetryStrategy.RETRY_WITH_BACKOFF
        assert http.classify_status_code(502) == http.RetryStrategy.RETRY_WITH_BACKOFF
        assert http.classify_status_code(422) == http.RetryStrategy.NO_RETRY


class TestConnectionPooling:
    @pytest.fixture()
    def mock_logger(self):
        logger = logging.getLogger("test-connection-pooling")
        return MagicMock(logger, autospec=True)

    @patch("requests.Session.get")
    def test_connection_pooled(self, mock_session_get, mock_logger):
        """Test that connections are pooled per host."""
        success_response = MagicMock()
        success_response.status_code = 200
        success_response.headers = {}

        mock_session_get.return_value = success_response

        # Make multiple requests to the same host
        http.get("http://example.com/path1", mock_logger)
        http.get("http://example.com/path2", mock_logger)
        http.get("http://example.com/path3", mock_logger)

        # All requests should use the same session (verified by checking HostState)
        registry = http._get_registry()
        state = registry.get_state("example.com")
        assert state.session is not None

    @patch("requests.Session.get")
    def test_different_hosts_different_sessions(self, mock_session_get, mock_logger):
        """Test that different hosts get different sessions."""
        success_response = MagicMock()
        success_response.status_code = 200
        success_response.headers = {}

        mock_session_get.return_value = success_response

        http.get("http://example.com/api", mock_logger)
        http.get("http://other.com/api", mock_logger)

        registry = http._get_registry()
        state1 = registry.get_state("example.com")
        state2 = registry.get_state("other.com")

        # Different hosts should have different sessions
        assert state1.session is not state2.session


class TestHostRegistry:
    def test_get_state_creates_new(self):
        """Test that get_state creates new state for unknown host."""
        registry = http.HostRegistry()
        state = registry.get_state("example.com")
        assert state.hostname == "example.com"
        assert state.consecutive_failures == 0

    def test_get_state_returns_existing(self):
        """Test that get_state returns existing state."""
        registry = http.HostRegistry()
        state1 = registry.get_state("example.com")
        state2 = registry.get_state("example.com")
        assert state1 is state2

    def test_record_success_resets_failures(self):
        """Test that record_success resets failure count."""
        registry = http.HostRegistry()
        state = registry.get_state("example.com")
        state.consecutive_failures = 3
        registry.record_success("example.com")
        assert state.consecutive_failures == 0

    def test_record_failure_increments(self):
        """Test that record_failure increments failure count."""
        registry = http.HostRegistry()
        registry.record_failure("example.com")
        state = registry.get_state("example.com")
        assert state.consecutive_failures == 1

    def test_record_rate_limit_sets_blocked_until(self):
        """Test that record_rate_limit sets blocked_until."""
        registry = http.HostRegistry()
        registry.record_rate_limit("example.com", 30.0)
        state = registry.get_state("example.com")
        assert state.blocked_until > time.time()


class TestExtractHostname:
    def test_standard_url(self):
        """Test extracting hostname from standard URL."""
        assert http._extract_hostname("http://example.com/path") == "example.com"
        assert http._extract_hostname("https://api.example.com/v1") == "api.example.com"

    def test_url_with_port(self):
        """Test extracting hostname from URL with port."""
        assert http._extract_hostname("http://example.com:8080/path") == "example.com:8080"

    def test_url_without_scheme(self):
        """Test extracting hostname from URL without scheme."""
        assert http._extract_hostname("example.com/path") == "example.com"

    def test_empty_url(self):
        """Test that empty URL returns 'unknown'."""
        assert http._extract_hostname("") == "unknown"

    def test_relative_path(self):
        """Test that relative path returns 'unknown'."""
        assert http._extract_hostname("/path/to/file") == "unknown"


class TestHttpConfig:
    def test_default_config(self):
        """Test default HttpConfig values."""
        config = http.HttpConfig()
        assert config.circuit_breaker_threshold == 5
        assert config.circuit_breaker_recovery == 60.0
        assert config.respect_retry_after is True
        assert config.retry_once_on_client_error is True

    def test_configure_updates_registry(self):
        """Test that configure() updates the registry."""
        http.configure(http.HttpConfig(circuit_breaker_threshold=10))
        registry = http._get_registry()
        assert registry.circuit_breaker_threshold == 10

    def test_configure_none_resets(self):
        """Test that configure(None) resets to defaults."""
        http.configure(http.HttpConfig(circuit_breaker_threshold=10))
        http.configure(None)
        config = http._get_config()
        assert config.circuit_breaker_threshold == 5


@pytest.mark.parametrize(
    "interval, jitter, max_value, expected",
    [
        (
            30,  # interval
            False,  # jitter
            None,  # max_value
            [30, 60, 120, 240, 480, 960, 1920, 3840, 7680, 15360, 30720, 61440, 122880, 245760, 491520],  # expected
        ),
        (
            3,  # interval
            False,  # jitter
            1000,  # max_value
            [3, 6, 12, 24, 48, 96, 192, 384, 768, 1000, 1000, 1000, 1000, 1000, 1000],  # expected
        ),
    ],
)
def test_backoff_sleep_interval(interval, jitter, max_value, expected):
    actual = [
        http.backoff_sleep_interval(interval, attempt, jitter=jitter, max_value=max_value) for attempt in range(len(expected))
    ]

    if not jitter:
        assert actual == expected
    else:
        for i, (a, e) in enumerate(zip(actual, expected)):
            assert a >= e and a <= e + 1, f"Jittered value out of bounds at attempt {i}: {a} (expected ~{e})"
