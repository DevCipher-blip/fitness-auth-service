from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from django.conf import settings

if not settings.configured:
    settings.configure(AWS_ACCESS_KEY_ID='', AWS_SECRET_ACCESS_KEY='', COGNITO_REGION='us-east-1', COGNITO_CLIENT_ID='local-test-client')


class IdentityBoundaryTests(TestCase):
    def setUp(self):
        import importlib
        import sys
        self.client = Mock()
        sys.modules.pop('accounts.schema', None)
        with patch('boto3.client', return_value=self.client):
            self.module = importlib.import_module('accounts.schema')
        self.client.get_user.return_value = {'Username': 'alice', 'UserAttributes': [{'Name': 'email', 'Value': 'alice@example.invalid'}]}

    def info(self, header=''):
        return SimpleNamespace(context=SimpleNamespace(META={'HTTP_AUTHORIZATION': header}))

    def test_lookup_requires_access_token(self):
        with self.assertRaisesRegex(ValueError, 'bearer'):
            self.module.Query.resolve_get_user(None, self.info(), 'alice')
        self.client.get_user.assert_not_called()
        self.client.admin_get_user.assert_not_called()

    def test_lookup_uses_token_scoped_identity(self):
        result = self.module.Query.resolve_get_user(None, self.info('Bearer test-token'), 'alice')
        self.assertEqual(result.email, 'alice@example.invalid')
        self.client.get_user.assert_called_once_with(AccessToken='test-token')
        self.client.admin_get_user.assert_not_called()

    def test_cross_user_lookup_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.module.Query.resolve_get_user(None, self.info('Bearer test-token'), 'bob')

    def test_signin_uses_returned_access_token(self):
        self.client.initiate_auth.return_value = {'AuthenticationResult': {'AccessToken': 'test-token', 'RefreshToken': 'test-refresh'}}
        result = self.module.SigninMutation.mutate(None, self.info(), 'alice', 'test-password')
        self.assertEqual(result.userName, 'alice')
        self.client.get_user.assert_called_once_with(AccessToken='test-token')
        self.client.admin_get_user.assert_not_called()

    def test_provider_errors_do_not_expose_raw_details(self):
        from botocore.exceptions import ClientError
        self.client.get_user.side_effect = ClientError({'Error': {'Code': 'NotAuthorizedException', 'Message': 'private-provider-detail'}}, 'GetUser')
        with self.assertRaisesRegex(ValueError, 'identity provider') as error:
            self.module.Query.resolve_get_user(None, self.info('Bearer invalid'), 'alice')
        self.assertNotIn('private-provider-detail', str(error.exception))
