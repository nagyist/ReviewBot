"""Unit tests for reviewbot.processing.review.File."""

from __future__ import unicode_literals

from reviewbot.testing import TestCase


class FileTests(TestCase):
    """Unit tests for reviewbot.processing.review.File."""

    def setUp(self):
        super(FileTests, self).setUp()

        self.review = self.create_review()
        self.review_file = self.create_review_file(
            self.review,
            diff_data=self.create_diff_data(chunks=[
                {
                    'change': 'insert',
                    'lines': [
                        'import foo',
                        'import bar',
                        'import baz',
                        'import foobarbaz',
                    ],
                    'new_linenum': 12,
                    'old_linenum': 11,
                },
                {
                    'change': 'replace',
                    'lines': [
                        ('except Exception:',
                         'except Exception as e:'),
                    ],
                    'new_linenum': 48,
                    'old_linenum': 44,
                },
                {
                    'change': 'delete',
                    'lines': [
                        '# Delete me',
                    ],
                    'new_linenum': 68,
                    'old_linenum': 65,
                },
                {
                    'change': 'insert',
                    'lines': [
                        'if foo():',
                        '    sys.exit(1)'
                    ],
                    'new_linenum': 69,
                    'old_linenum': 66,
                },
            ]))

    def test_comment(self):
        """Testing File.comment"""
        self.review_file.comment('This is a comment',
                                 first_line=12)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_line_range(self):
        """Testing File.comment with line range"""
        self.review_file.comment('This is a comment',
                                 first_line=12,
                                 num_lines=2)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 2,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_first_line_0(self):
        """Testing File.comment with first_line=0"""
        self.review_file.comment('This is a comment',
                                 first_line=0)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 1,
            'issue_opened': True,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_first_line_none(self):
        """Testing File.comment with first_line=0"""
        self.review_file.comment('This is a comment',
                                 first_line=None)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 1,
            'issue_opened': True,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_unmodified_line_range(self):
        """Testing File.comment on unmodified line range"""
        self.review_file.comment('This is a comment',
                                 first_line=1,
                                 num_lines=2)

        self.assertEqual(self.review.comments, [])

    def test_comment_with_unmodified_line_range_with_comment_unmodified(self):
        """Testing File.comment on unmodified line range with
        comment_unmodified=True
        """
        self.review.settings['comment_unmodified'] = True
        self.review_file.comment('This is a comment',
                                 first_line=1,
                                 num_lines=2)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 1,
            'issue_opened': True,
            'num_lines': 2,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_issue_true(self):
        """Testing File.comment with issue=False"""
        self.review_file.comment('This is a comment',
                                 first_line=12,
                                 issue=True)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_issue_false(self):
        """Testing File.comment with issue=False"""
        self.review_file.comment('This is a comment',
                                 first_line=12,
                                 issue=False)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': False,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_issue_none_and_setting_true(self):
        """Testing File.comment with issue=None and
        settings['open_issues']=True
        """
        self.review.settings['open_issues'] = True
        self.review_file.comment('This is a comment',
                                 first_line=12)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_issue_none_and_setting_false(self):
        """Testing File.comment with issue=None and
        settings['open_issues']=False
        """
        self.review.settings['open_issues'] = False
        self.review_file.comment('This is a comment',
                                 first_line=12)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': False,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': False,
        }])

    def test_comment_with_rich_text_true(self):
        """Testing File.comment with rich_text=True"""
        self.review_file.comment('This is a comment',
                                 first_line=12,
                                 rich_text=True)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': 'This is a comment',
            'rich_text': True,
        }])

    def test_comment_with_start_column(self):
        """Testing File.comment with start_column"""
        self.review_file.comment('This is a comment',
                                 first_line=12,
                                 start_column=10)

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': (
                'This is a comment\n'
                '\n'
                'Column: 10'
            ),
            'rich_text': False,
        }])

    def test_comment_with_error_code(self):
        """Testing File.comment with error_code"""
        self.review_file.comment('This is a comment',
                                 first_line=12,
                                 error_code='W123')

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': (
                'This is a comment\n'
                '\n'
                'Error code: W123'
            ),
            'rich_text': False,
        }])

    def test_comment_with_severity(self):
        """Testing File.comment with severity"""
        self.review_file.comment('This is a comment',
                                 first_line=12,
                                 severity='warning')

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': (
                'This is a comment\n'
                '\n'
                'Severity: warning'
            ),
            'rich_text': False,
        }])

    def test_comment_with_text_extra(self):
        """Testing File.comment with text_extra"""
        self.review_file.comment(
            'This is a comment',
            first_line=12,
            text_extra=[
                ('Header1', 'value1'),
                ('Header2', 'value2'),
            ])

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': (
                'This is a comment\n'
                '\n'
                'Header1: value1\n'
                'Header2: value2'
            ),
            'rich_text': False,
        }])

    def test_comment_with_all_extra_info(self):
        """Testing File.comment with all extra information appended to text"""
        self.review_file.comment(
            'This is a comment',
            first_line=12,
            start_column=10,
            severity='style',
            error_code='W123',
            text_extra=[
                ('Header1', 'value1'),
                ('Header2', 'value2'),
            ])

        self.assertEqual(self.review.comments, [{
            'filediff_id': 42,
            'first_line': 12,
            'issue_opened': True,
            'num_lines': 1,
            'text': (
                'This is a comment\n'
                '\n'
                'Column: 10\n'
                'Severity: style\n'
                'Error code: W123\n'
                'Header1: value1\n'
                'Header2: value2'
            ),
            'rich_text': False,
        }])

    def test_get_files_with_original_false(self):
        """Testing File.get_lines with original=False"""
        # Test a bunch of ranges, to make sure we don't have any boundary
        # issues.
        review_file = self.review_file

        self.assertEqual(
            review_file.get_lines(1, 4),
            [
                '==',
                '==',
                '==',
                '==',
            ])
        self.assertEqual(
            review_file.get_lines(10, 4),
            [
                '==',
                '==',
                'import foo',
                'import bar',
            ])
        self.assertEqual(
            review_file.get_lines(13, 1),
            ['import bar'])
        self.assertEqual(
            review_file.get_lines(47, 3),
            [
                '==',
                'except Exception as e:',
                '==',
            ])
        self.assertEqual(
            review_file.get_lines(68, 2),
            [
                '==',
                'if foo():'
            ])

        self.assertEqual(
            review_file.get_lines(71, 1),
            [])
        self.assertEqual(
            review_file.get_lines(1000, 2),
            [])

    def test_get_files_with_original_true(self):
        """Testing File.get_lines with original=False"""
        # Test a bunch of ranges, to make sure we don't have any boundary
        # issues.
        review_file = self.review_file

        self.assertEqual(
            review_file.get_lines(1, 4, original=True),
            [
                '==',
                '==',
                '==',
                '==',
            ])
        self.assertEqual(
            review_file.get_lines(10, 4, original=True),
            [
                '==',
                '==',
                '==',
                '==',
            ])
        self.assertEqual(
            review_file.get_lines(43, 3, original=True),
            [
                '==',
                'except Exception:',
                '==',
            ])
        self.assertEqual(
            review_file.get_lines(64, 2, original=True),
            [
                '==',
                '# Delete me',
            ])
        self.assertEqual(
            review_file.get_lines(65, 2, original=True),
            [
                '# Delete me',
            ])

        self.assertEqual(
            review_file.get_lines(66, 1, original=True),
            [])
        self.assertEqual(
            review_file.get_lines(1000, 2, original=True),
            [])

    def test_translate_line_num_with_original_false(self):
        """Testing File._translate_line_num with original=False"""
        # Test a bunch of ranges, to make sure we don't have any boundary
        # issues. We're going to check the beginning, end, and a rough
        # midpoint of each chunk.
        review_file = self.review_file

        test_data = [
            # Equals chunk.
            (1, 1),
            (5, 5),
            (11, 11),

            # Inserts chunk.
            (12, 12),
            (13, 13),
            (15, 15),

            # Equals chunk.
            (16, 16),
            (32, 32),
            (47, 47),

            # Replaces chunk.
            (48, 48),

            # Equals chunk.
            (49, 49),
            (58, 58),
            (68, 68),

            # Inserts chunk.
            (69, 70),
            (70, 71),

            # Bad numbers.
            (0, None),
            (-1, None),
            (72, None),
            (1000, None),
        ]

        for line_num, expected_vline_num in test_data:
            self.assertEqual(
                review_file._translate_line_num(line_num, original=False),
                expected_vline_num,
                'Line number %s did not map to virtual line number %s'
                % (line_num, expected_vline_num))

    def test_translate_line_num_with_original_true(self):
        """Testing File._translate_line_num with original=True"""
        # Test a bunch of ranges, to make sure we don't have any boundary
        # issues. We're going to check the beginning, end, and a rough
        # midpoint of each chunk.
        review_file = self.review_file

        test_data = [
            # Equals chunk.
            (1, 1),
            (5, 5),
            (11, 11),

            # Equals chunk.
            (12, 16),
            (28, 32),
            (43, 47),

            # Replaces chunk.
            (44, 48),

            # Equals chunk.
            (45, 49),
            (54, 58),
            (64, 68),

            # Deletes chunk.
            (65, 69),

            # Bad numbers.
            (0, None),
            (-1, None),
            (66, None),
            (1000, None),
        ]

        for line_num, expected_vline_num in test_data:
            self.assertEqual(
                review_file._translate_line_num(line_num, original=True),
                expected_vline_num,
                'Line number %s did not map to virtual line number %s'
                % (line_num, expected_vline_num))

    def test_is_modified_with_original_false(self):
        """Testing File._is_modified with original=False"""
        # Test a bunch of ranges, to make sure we don't have any boundary
        # issues. We're going to test within and across chunk boundaries.
        review_file = self.review_file

        test_data = [
            # Equals chunk.
            (1, 3, False),
            (11, 1, False),

            # Cross equals/inserts chunks.
            (11, 2, True),

            # Inserts chunk.
            (12, 1, True),
            (13, 3, True),
            (15, 1, True),

            # Cross inserts/equals chunks.
            (15, 2, True),

            # Equals chunk.
            (16, 1, False),
            (16, 5, False),
            (47, 1, False),

            # Cross equals/replaces chunks.
            (47, 2, True),

            # Replaces chunk.
            (48, 1, True),

            # Cross replaces/equals chunks.
            (48, 2, True),

            # Equals chunk.
            (49, 1, False),
            (52, 5, False),
            (68, 1, False),

            # Cross equals/inserts chunks.
            (68, 2, True),

            # Inserts chunk.
            (69, 1, True),
            (69, 2, True),

            # Cross inserts/out-of-bounds.
            (69, 10, True),

            # Full change.
            (1, 10000, True),

            # Bad numbers.
            (0, 1, False),
            (-1, 1, False),
            (1000, 1, False),
        ]

        for line_num, num_lines, expected_is_modified in test_data:
            self.assertIs(
                review_file._is_modified(line_num, num_lines, original=False),
                expected_is_modified,
                'Modified state for line range %s-%s was expected to be %s'
                % (line_num, line_num + num_lines, expected_is_modified))

    def test_is_modified_with_original_true(self):
        """Testing File._is_modified with original=True"""
        # Test a bunch of ranges, to make sure we don't have any boundary
        # issues. We're going to test within and across chunk boundaries.
        review_file = self.review_file

        test_data = [
            # Equals chunk.
            (1, 3, False),
            (11, 1, False),

            # Cross equals/equals chunks.
            (11, 2, False),

            # Equals chunk.
            (12, 1, False),
            (28, 5, False),
            (43, 1, False),

            # Cross equals/replaces chunks.
            (43, 2, True),

            # Replaces chunk.
            (44, 1, True),

            # Cross replaces/equals chunks.
            (44, 2, True),

            # Equals chunk.
            (45, 1, False),
            (52, 5, False),
            (64, 1, False),

            # Cross equals/deletes chunks.
            (64, 2, True),

            # Deletes chunk.
            (65, 1, True),

            # Cross deletes/out-of-bounds.
            (65, 10, True),

            # Full change.
            (1, 10000, True),

            # Bad numbers.
            (0, 1, False),
            (-1, 1, False),
            (1000, 1, False),
        ]

        for line_num, num_lines, expected_is_modified in test_data:
            self.assertIs(
                review_file._is_modified(line_num, num_lines, original=True),
                expected_is_modified,
                'Modified state for line range %s-%s was expected to be %s'
                % (line_num, line_num + num_lines, expected_is_modified))