"""Unit tests for reviewbot.utils.process."""

from __future__ import annotations

import os
import shutil
import tempfile
from typing import ClassVar

from reviewbot.testing import TestCase
from reviewbot.utils.process import is_exe_in_path


class IsExeInPathTests(TestCase):
    """Unit tests for reviewbot.utils.process.is_exe_in_path."""

    #: The filename of the command to execute.
    exe_filename: ClassVar[str]

    #: The temporary directory used during the test case.
    tempdir: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the test case class."""
        super().setUpClass()

        cls.tempdir = tempfile.mkdtemp()
        cls.exe_filename = os.path.join(cls.tempdir, 'test.sh')

        # We can freely set this here, because the parent class is going to
        # handle resetting it in tearDownClass().
        os.environ['PATH'] = f'/xxx/abc:{cls.tempdir}:/xxx/def'

        with open(cls.exe_filename, 'w') as fp:
            fp.write('#!/bin/sh\n')

        os.chmod(cls.exe_filename, 0o755)

    @classmethod
    def tearDownClass(cls) -> None:
        """Tear down the test case class."""
        super().tearDownClass()

        shutil.rmtree(cls.tempdir)

    def test_with_found_in_path(self) -> None:
        """Testing is_exe_in_path with executable found in path"""
        cache = {}

        self.assertTrue(is_exe_in_path('test.sh', cache=cache))
        self.assertEqual(cache, {
            'test.sh': self.exe_filename,
        })

    def test_with_not_found_in_path(self) -> None:
        """Testing is_exe_in_path with executable not found in path"""
        cache = {}

        self.assertFalse(is_exe_in_path('bad.sh', cache=cache))
        self.assertEqual(cache, {
            'bad.sh': None,
        })

    def test_with_with_abs_path_found(self) -> None:
        """Testing is_exe_in_path with absolute path and found"""
        cache = {}

        self.assertTrue(is_exe_in_path(self.exe_filename, cache=cache))
        self.assertEqual(cache, {
            self.exe_filename: self.exe_filename,
        })

    def test_with_with_abs_path_not_found(self) -> None:
        """Testing is_exe_in_path with absolute path and not found"""
        cache = {}

        self.assertFalse(is_exe_in_path('/xxx/bad.sh', cache=cache))
        self.assertEqual(cache, {
            '/xxx/bad.sh': None,
        })
