import datetime
from unittest.mock import Mock, MagicMock
import pytest
from vunnel.tool.fixdate.finder import Finder, Result, Strategy


class TestFinder:
    """Test class for the Finder.best() method."""

    def create_mock_strategy(self, results):
        """helper to create a mock strategy that returns specified results."""
        mock_strategy = Mock(spec=Strategy)
        mock_strategy.find.return_value = results
        return mock_strategy

    def create_result(self, date_str=None, kind="test", version=None, accurate=None):
        """helper to create Result objects with specified parameters."""
        date_obj = None
        if date_str:
            date_obj = datetime.date.fromisoformat(date_str)
        return Result(date=date_obj, kind=kind, version=version, accurate=accurate)

    def test_best_returns_none_when_no_fix_version(self):
        """Test that best() returns None when fix_version is missing or invalid."""
        strategy = self.create_mock_strategy([])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        # test None fix_version
        result = finder.best("CVE-2023-0001", "package", None)
        assert result is None

        # test empty string fix_version
        result = finder.best("CVE-2023-0001", "package", "")
        assert result is None

        # test "None" string fix_version
        result = finder.best("CVE-2023-0001", "package", "None")
        assert result is None

        # test "0" fix_version (nak conditions... these by definition are NOT fixes)
        result = finder.best("CVE-2023-0001", "package", "0")
        assert result is None

    def test_best_with_high_quality_candidates(self):
        """Test that high quality candidates (accurate=True) are prioritized first."""
        strategy = self.create_mock_strategy([])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        high_quality = self.create_result("2023-01-01", "candidate", accurate=True)
        low_quality = self.create_result("2023-01-02", "candidate", accurate=False)
        candidates = [low_quality, high_quality]  # intentionally out of order

        result = finder.best("CVE-2023-0001", "package", "1.0.0", candidates=candidates)

        assert result == high_quality
        assert result.date == datetime.date(2023, 1, 1)

    def test_best_with_low_quality_candidates_as_fallback(self):
        """Test that low quality candidates are used when no high quality ones exist."""
        strategy = self.create_mock_strategy([])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        low_quality = self.create_result("2023-01-02", "candidate", accurate=False)
        candidates = [low_quality]

        result = finder.best("CVE-2023-0001", "package", "1.0.0", candidates=candidates)

        assert result == low_quality
        assert result.date == datetime.date(2023, 1, 2)

    def test_best_with_strategy_results(self):
        """Test that strategy results are included in the prioritization."""
        strategy_result = self.create_result("2023-01-03", "strategy")
        strategy = self.create_mock_strategy([strategy_result])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        assert result == strategy_result
        strategy.find.assert_called_once_with("CVE-2023-0001", "package", "1.0.0", None)

    def test_best_prioritization_order(self):
        """Test the full prioritization order: high quality candidates → strategies → low quality candidates."""
        strategy_result = self.create_result("2023-01-05", "strategy")
        strategy = self.create_mock_strategy([strategy_result])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        high_quality = self.create_result("2023-01-01", "candidate", accurate=True)
        low_quality = self.create_result("2023-01-02", "candidate", accurate=False)
        candidates = [low_quality, high_quality]

        result = finder.best("CVE-2023-0001", "package", "1.0.0", candidates=candidates)

        # should return high quality candidate first
        assert result == high_quality

    def test_best_with_accurate_first_observed_filters_results(self):
        """Test that accurate first observed date filters out later results."""
        strategy_result = self.create_result("2023-01-10", "strategy")  # after first observed
        strategy = self.create_mock_strategy([strategy_result])

        first_observed_result = self.create_result("2023-01-05", "first_observed", accurate=True)
        first_observed = self.create_mock_strategy([first_observed_result])

        finder = Finder([strategy], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        # should return first observed since strategy result is after it
        assert result == first_observed_result

    def test_best_with_accurate_first_observed_allows_earlier_results(self):
        """Test that results before accurate first observed date are allowed."""
        strategy_result = self.create_result("2023-01-03", "strategy")  # before first observed
        strategy = self.create_mock_strategy([strategy_result])

        first_observed_result = self.create_result("2023-01-05", "first_observed", accurate=True)
        first_observed = self.create_mock_strategy([first_observed_result])

        finder = Finder([strategy], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        # should return strategy result since it's before first observed
        assert result == strategy_result

    def test_best_returns_first_observed_when_no_valid_candidates(self):
        """Test fallback to first observed when all other results are filtered out."""
        strategy_result = self.create_result("2023-01-10", "strategy")  # after first observed
        strategy = self.create_mock_strategy([strategy_result])

        first_observed_result = self.create_result("2023-01-05", "first_observed", accurate=True)
        first_observed = self.create_mock_strategy([first_observed_result])

        finder = Finder([strategy], first_observed)

        high_quality = self.create_result("2023-01-15", "candidate", accurate=True)  # after first observed
        candidates = [high_quality]

        result = finder.best("CVE-2023-0001", "package", "1.0.0", candidates=candidates)

        # should return first observed since all other candidates are after it
        assert result == first_observed_result

    def test_best_with_inaccurate_first_observed_as_last_resort(self):
        """Test that inaccurate first observed dates are used as last resort."""
        strategy_result = self.create_result("2023-01-03", "strategy")
        strategy = self.create_mock_strategy([strategy_result])

        first_observed_result = self.create_result("2023-01-05", "first_observed", accurate=False)
        first_observed = self.create_mock_strategy([first_observed_result])

        finder = Finder([strategy], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        # should return strategy result first, then first observed is added to results
        assert result == strategy_result

    def test_best_with_no_results(self):
        """Test that None is returned when no results are available from any source."""
        strategy = self.create_mock_strategy([])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        assert result is None

    def test_best_with_empty_strategies(self):
        """Test behavior when strategies list is empty."""
        first_observed_result = self.create_result("2023-01-05", "first_observed", accurate=False)
        first_observed = self.create_mock_strategy([first_observed_result])

        finder = Finder([], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        assert result == first_observed_result

    def test_best_with_none_dates_in_results(self):
        """Test handling of Result objects with None dates."""
        strategy_result_no_date = Result(date=None, kind="strategy")
        strategy_result_with_date = self.create_result("2023-01-03", "strategy")
        strategy = self.create_mock_strategy([strategy_result_no_date, strategy_result_with_date])

        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        # the best() method returns the first result from strategies, even if it has None date
        # this is the actual behavior - strategy results are not filtered for None dates
        assert result == strategy_result_no_date

    def test_best_with_mixed_accurate_and_inaccurate_results(self):
        """Test proper ordering when mixing accurate and inaccurate results."""
        strategy1_result = self.create_result("2023-01-10", "strategy1")
        strategy1 = self.create_mock_strategy([strategy1_result])

        strategy2_result = self.create_result("2023-01-08", "strategy2")
        strategy2 = self.create_mock_strategy([strategy2_result])

        first_observed = self.create_mock_strategy([])

        # strategies are ordered by priority
        finder = Finder([strategy1, strategy2], first_observed)

        high_quality = self.create_result("2023-01-12", "candidate", accurate=True)
        low_quality = self.create_result("2023-01-01", "candidate", accurate=False)
        candidates = [low_quality, high_quality]

        result = finder.best("CVE-2023-0001", "package", "1.0.0", candidates=candidates)

        # should return high quality candidate first, regardless of date
        assert result == high_quality

    def test_best_multiple_strategies_priority_order(self):
        """Test that strategies are called in order and results prioritized by strategy order."""
        strategy1_result = self.create_result("2023-01-10", "strategy1")
        strategy1 = self.create_mock_strategy([strategy1_result])

        strategy2_result = self.create_result("2023-01-05", "strategy2")  # earlier date but lower priority
        strategy2 = self.create_mock_strategy([strategy2_result])

        first_observed = self.create_mock_strategy([])

        # strategy1 has higher priority than strategy2
        finder = Finder([strategy1, strategy2], first_observed)

        result = finder.best("CVE-2023-0001", "package", "1.0.0")

        # should return strategy1 result since it has higher priority
        assert result == strategy1_result

    def test_best_with_ecosystem_parameter(self):
        """Test that ecosystem parameter is passed to strategies correctly."""
        strategy = self.create_mock_strategy([self.create_result("2023-01-01", "strategy")])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        finder.best("CVE-2023-0001", "package", "1.0.0", ecosystem="npm")

        strategy.find.assert_called_once_with("CVE-2023-0001", "package", "1.0.0", "npm")
        first_observed.find.assert_called_once_with("CVE-2023-0001", "package", "1.0.0", "npm")

    def test_best_candidates_with_no_date_are_filtered_out(self):
        """Test that candidates without dates are filtered out during prioritization."""
        strategy = self.create_mock_strategy([])
        first_observed = self.create_mock_strategy([])
        finder = Finder([strategy], first_observed)

        high_quality_no_date = Result(date=None, kind="candidate", accurate=True)
        high_quality_with_date = self.create_result("2023-01-01", "candidate", accurate=True)
        candidates = [high_quality_no_date, high_quality_with_date]

        result = finder.best("CVE-2023-0001", "package", "1.0.0", candidates=candidates)

        # should return the candidate with a date
        assert result == high_quality_with_date
