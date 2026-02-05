"""
Tests for auth checks with PostgreSQL-specific constraints.
"""

from django.contrib.auth.checks import check_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.core import checks
from django.db import models
from django.test import override_settings, override_system_checks
from django.test.utils import isolate_apps

from . import PostgreSQLSimpleTestCase

try:
    from django.contrib.postgres.constraints import ExclusionConstraint
    from django.contrib.postgres.fields import RangeOperators
except ImportError:
    pass


@isolate_apps("postgres_tests", attr_name="apps")
@override_system_checks([check_user_model])
class UserModelHashExclusionConstraintTests(PostgreSQLSimpleTestCase):
    """
    Tests that hash exclusion constraints are recognized as unique constraints
    for the USERNAME_FIELD check.
    """

    @override_settings(AUTH_USER_MODEL="postgres_tests.UserWithHashExclusion")
    def test_username_unique_with_hash_exclusion_constraint(self):
        """
        A hash exclusion constraint with EQUAL operator on the USERNAME_FIELD
        should be recognized as a unique constraint (no auth.E003 error).
        """

        class UserWithHashExclusion(AbstractBaseUser):
            username = models.CharField(max_length=30)
            USERNAME_FIELD = "username"

            class Meta:
                app_label = "postgres_tests"
                constraints = [
                    ExclusionConstraint(
                        name="username_hash_unique",
                        expressions=[("username", RangeOperators.EQUAL)],
                        index_type="hash",
                    ),
                ]

        errors = checks.run_checks(app_configs=self.apps.get_app_configs())
        self.assertEqual(errors, [])

    @override_settings(AUTH_USER_MODEL="postgres_tests.UserWithHashExclusionF")
    def test_username_unique_with_hash_exclusion_constraint_f_expression(self):
        """
        A hash exclusion constraint using F() expression should also be
        recognized as a unique constraint.
        """
        from django.db.models import F

        class UserWithHashExclusionF(AbstractBaseUser):
            username = models.CharField(max_length=30)
            USERNAME_FIELD = "username"

            class Meta:
                app_label = "postgres_tests"
                constraints = [
                    ExclusionConstraint(
                        name="username_hash_unique_f",
                        expressions=[(F("username"), RangeOperators.EQUAL)],
                        index_type="hash",
                    ),
                ]

        errors = checks.run_checks(app_configs=self.apps.get_app_configs())
        self.assertEqual(errors, [])

    @override_settings(AUTH_USER_MODEL="postgres_tests.UserWithGistExclusion")
    def test_username_not_unique_with_gist_exclusion_constraint(self):
        """
        A GiST exclusion constraint should NOT be recognized as a unique
        constraint, even with EQUAL operator.
        """

        class UserWithGistExclusion(AbstractBaseUser):
            username = models.CharField(max_length=30)
            USERNAME_FIELD = "username"

            class Meta:
                app_label = "postgres_tests"
                constraints = [
                    ExclusionConstraint(
                        name="username_gist_exclusion",
                        expressions=[("username", RangeOperators.EQUAL)],
                        index_type="gist",
                    ),
                ]

        errors = checks.run_checks(app_configs=self.apps.get_app_configs())
        self.assertEqual(
            errors,
            [
                checks.Error(
                    "'UserWithGistExclusion.username' must be unique because "
                    "it is named as the 'USERNAME_FIELD'.",
                    obj=UserWithGistExclusion,
                    id="auth.E003",
                ),
            ],
        )

    @override_settings(AUTH_USER_MODEL="postgres_tests.UserWithConditionalHash")
    def test_username_not_unique_with_conditional_hash_exclusion(self):
        """
        A hash exclusion constraint with a condition should NOT be recognized
        as a unique constraint (it's a partial constraint).
        """
        from django.db.models import Q

        class UserWithConditionalHash(AbstractBaseUser):
            username = models.CharField(max_length=30)
            is_active = models.BooleanField(default=True)
            USERNAME_FIELD = "username"

            class Meta:
                app_label = "postgres_tests"
                constraints = [
                    ExclusionConstraint(
                        name="username_hash_conditional",
                        expressions=[("username", RangeOperators.EQUAL)],
                        index_type="hash",
                        condition=Q(is_active=True),
                    ),
                ]

        errors = checks.run_checks(app_configs=self.apps.get_app_configs())
        self.assertEqual(
            errors,
            [
                checks.Error(
                    "'UserWithConditionalHash.username' must be unique because "
                    "it is named as the 'USERNAME_FIELD'.",
                    obj=UserWithConditionalHash,
                    id="auth.E003",
                ),
            ],
        )
