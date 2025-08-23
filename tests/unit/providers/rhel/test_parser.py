import os
import tempfile
import shutil
from unittest.mock import Mock, patch, call

import pytest

from vunnel.providers.rhel import parser


class TestHandleHydraData:

    @pytest.fixture
    def mock_logger(self):
        return Mock()

    @pytest.fixture
    def temp_dirs(self):
        with tempfile.TemporaryDirectory() as temp_root:
            dir_path = os.path.join(temp_root, "main_dir")
            backup_dir_path = os.path.join(temp_root, "backup_dir")
            yield dir_path, backup_dir_path

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_ignore_hydra_errors_true_with_existing_dir(self, mock_move_dir, mock_silent_remove,
                                                        mock_exists, mock_makedirs, mock_logger):
        """Test behavior when ignore_hydra_errors=True and directory exists."""
        mock_exists.return_value = True

        dir_path = "/tmp/test/dir"
        backup_dir_path = "/tmp/test/backup"

        with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
            pass

        mock_silent_remove.assert_called_with(backup_dir_path, tree=True)
        mock_makedirs.assert_has_calls([call(dir_path)])
        mock_move_dir.assert_called_once_with(dir_path, backup_dir_path)
        mock_logger.debug.assert_called_with(f"moving existing {dir_path} to {backup_dir_path}")

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_ignore_hydra_errors_true_without_existing_dir(self, mock_move_dir, mock_silent_remove,
                                                           mock_exists, mock_makedirs, mock_logger):
        """Test behavior when ignore_hydra_errors=True and directory doesn't exist."""
        mock_exists.return_value = False

        dir_path = "/tmp/test/dir"
        backup_dir_path = "/tmp/test/backup"

        with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
            pass

        mock_silent_remove.assert_called_once_with(backup_dir_path, tree=True)
        mock_makedirs.assert_has_calls([call(dir_path)])
        mock_move_dir.assert_not_called()
        mock_logger.debug.assert_called_with(f"no existing {dir_path} to move, starting fresh")

    @patch('os.makedirs')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    def test_ignore_hydra_errors_false(self, mock_silent_remove, mock_makedirs, mock_logger):
        """Test behavior when ignore_hydra_errors=False."""
        dir_path = "/tmp/test/dir"
        backup_dir_path = "/tmp/test/backup"

        with parser.handle_hydra_data(False, dir_path, backup_dir_path, mock_logger):
            pass

        # Verify only dir_path is removed and recreated
        mock_silent_remove.assert_called_once_with(dir_path, tree=True)
        mock_makedirs.assert_called_once_with(dir_path)

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_exception_with_ignore_hydra_errors_true(self, mock_move_dir, mock_silent_remove,
                                                     mock_exists, mock_makedirs, mock_logger):
        """Test exception handling when ignore_hydra_errors=True."""
        mock_exists.return_value = True

        dir_path = "/tmp/test/dir"
        backup_dir_path = "/tmp/test/backup"
        test_exception = ValueError("Test error")

        # Exception should be caught and handled, not re-raised
        with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
            raise test_exception

        # verify restoration calls (2 silent_remove calls: setup + restoration)
        assert mock_silent_remove.call_count == 2
        mock_silent_remove.assert_has_calls([
            call(backup_dir_path, tree=True),  # Setup
            call(dir_path, tree=True)          # Restoration
        ])

        # verify move operations (2 calls: setup + restoration)
        assert mock_move_dir.call_count == 2
        mock_move_dir.assert_has_calls([
            call(dir_path, backup_dir_path),   # Setup
            call(backup_dir_path, dir_path)    # Restoration
        ])

    @patch('os.makedirs')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    def test_exception_with_ignore_hydra_errors_false(self, mock_silent_remove, mock_makedirs, mock_logger):
        """Test exception handling when ignore_hydra_errors=False."""
        dir_path = "/tmp/test/dir"
        backup_dir_path = "/tmp/test/backup"
        test_exception = ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            with parser.handle_hydra_data(False, dir_path, backup_dir_path, mock_logger):
                raise test_exception

        # verify error is logged
        mock_logger.error.assert_called_with(f"error processing minimal CVE pages: {test_exception}")
        # no restoration debug message should be logged
        assert not any(call.args[0] == "restoring backup directory" for call in mock_logger.debug.call_args_list)

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_makedirs_called_correctly(self, mock_move_dir, mock_silent_remove,
                                       mock_exists, mock_makedirs, mock_logger):
        """Test that os.makedirs is called with correct parameters."""
        mock_exists.return_value = False

        dir_path = "/tmp/test/dir"
        backup_dir_path = "/tmp/test/backup"

        with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
            pass

        # verify makedirs called for the main directory only (backup should not be created since only move operations will place it)
        expected_calls = [call(dir_path)]
        mock_makedirs.assert_has_calls(expected_calls)
        assert mock_makedirs.call_count == 1

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_logging_messages(self, mock_move_dir, mock_silent_remove,
                              mock_exists, mock_makedirs, mock_logger):
        """Test that appropriate logging messages are generated."""
        dir_path = "/custom/path"
        backup_dir_path = "/custom/backup"

        # test with existing directory
        mock_exists.return_value = True
        with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
            pass

        mock_logger.debug.assert_called_with(f"moving existing {dir_path} to {backup_dir_path}")

        # reset and test without existing directory
        mock_logger.reset_mock()
        mock_exists.return_value = False

        with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
            pass

        mock_logger.debug.assert_called_with(f"no existing {dir_path} to move, starting fresh")

    def test_real_filesystem_operations(self, temp_dirs, mock_logger):
        """Integration test with real filesystem operations."""
        dir_path, backup_dir_path = temp_dirs

        # create initial directory with some content
        os.makedirs(dir_path)
        test_file = os.path.join(dir_path, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")

        with patch('vunnel.providers.rhel.parser.utils.silent_remove', side_effect=lambda path, tree=False: shutil.rmtree(path) if tree and os.path.exists(path) else None):
            with patch('vunnel.providers.rhel.parser.utils.move_dir', side_effect=shutil.move):
                # test successful execution
                with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
                    # directory should exist and be empty
                    assert os.path.exists(dir_path)
                    assert len(os.listdir(dir_path)) == 0

                # recreate the directory with content
                os.makedirs(dir_path, exist_ok=True)
                with open(test_file, "w") as f:
                    f.write("test content")

                # now test exception handling
                with parser.handle_hydra_data(True, dir_path, backup_dir_path, mock_logger):
                    raise ValueError("Test error")

                # directory should be restored with original content
                assert os.path.exists(dir_path)
                assert os.path.exists(test_file)
                with open(test_file, "r") as f:
                    assert f.read() == "test content"

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_parameter_combinations(self, mock_move_dir, mock_silent_remove,
                                    mock_exists, mock_makedirs, mock_logger):
        """Test different parameter combinations."""
        test_cases = [
            (True, True),   # ignore_hydra_errors=True, dir exists
            (True, False),  # ignore_hydra_errors=True, dir doesn't exist
            (False, True),  # ignore_hydra_errors=False, dir exists
            (False, False), # ignore_hydra_errors=False, dir doesn't exist
        ]

        for ignore_errors, dir_exists in test_cases:
            mock_exists.return_value = dir_exists
            mock_makedirs.reset_mock()
            mock_silent_remove.reset_mock()
            mock_move_dir.reset_mock()
            mock_logger.reset_mock()

            with parser.handle_hydra_data(ignore_errors, "/tmp/test/dir", "/tmp/test/backup", mock_logger):
                pass

            # all cases should create the main directory
            mock_makedirs.assert_called_with("/tmp/test/dir")

            if ignore_errors:
                # should always remove backup dir and create the main dir (not create the backup dir, since only move operations will place it)
                mock_silent_remove.assert_any_call("/tmp/test/backup", tree=True)
                mock_makedirs.assert_any_call("/tmp/test/dir")

                if dir_exists:
                    # should move existing dir to backup
                    mock_move_dir.assert_called_once_with("/tmp/test/dir", "/tmp/test/backup")
                else:
                    # should not move anything
                    mock_move_dir.assert_not_called()
            else:
                # should only remove main dir
                mock_silent_remove.assert_called_once_with("/tmp/test/dir", tree=True)


    @patch('os.makedirs', side_effect=OSError("Permission denied"))
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    def test_makedirs_failure(self, mock_silent_remove, mock_makedirs, mock_logger):
        """Test behavior when os.makedirs fails."""
        with pytest.raises(OSError, match="Permission denied"):
            with parser.handle_hydra_data(False, "/tmp/test/dir", "/tmp/test/backup", mock_logger):
                pass

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir', side_effect=OSError("Move failed"))
    def test_move_dir_failure_during_setup(self, mock_move_dir, mock_silent_remove,
                                           mock_exists, mock_makedirs, mock_logger):
        """Test behavior when vunnel.providers.rhel.parser.utils.move_dir fails during setup."""
        mock_exists.return_value = True

        with pytest.raises(OSError, match="Move failed"):
            with parser.handle_hydra_data(True, "/tmp/test/dir", "/tmp/test/backup", mock_logger):
                pass

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_multiple_exceptions(self, mock_move_dir, mock_silent_remove,
                                 mock_exists, mock_makedirs, mock_logger):
        """Test handling of multiple different exception types."""
        mock_exists.return_value = True

        exception_types = [
            ValueError("Value error"),
            RuntimeError("Runtime error"),
            KeyError("Key error"),
            FileNotFoundError("File not found"),
        ]

        for exception in exception_types:
            mock_logger.reset_mock()

            with parser.handle_hydra_data(True, "/tmp/test/dir", "/tmp/test/backup", mock_logger):
                raise exception

            # should log the specific exception
            mock_logger.error.assert_called_with(f"error processing minimal CVE pages: {exception}")

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove', side_effect=OSError("Cleanup failed"))
    @patch('vunnel.providers.rhel.parser.utils.move_dir')
    def test_cleanup_failure_during_exception_handling(self, mock_move_dir, mock_silent_remove,
                                                       mock_exists, mock_makedirs, mock_logger):
        """Test behavior when cleanup operations fail during exception handling."""
        mock_exists.return_value = True

        # the context manager should still handle the original exception properly
        # even if cleanup fails
        with pytest.raises(OSError, match="Cleanup failed"):
            with parser.handle_hydra_data(True, "/tmp/test/dir", "/tmp/test/backup", mock_logger):
                raise ValueError("Original error")

    @patch('os.makedirs')
    @patch('vunnel.providers.rhel.parser.utils.silent_remove')
    def test_empty_paths(self, mock_silent_remove, mock_makedirs, mock_logger):
        """Test behavior with empty or unusual path strings."""
        # test with empty strings
        with parser.handle_hydra_data(False, "", "/tmp/backup", mock_logger):
            pass

        mock_makedirs.assert_called_with("")
        mock_silent_remove.assert_called_with("", tree=True)
