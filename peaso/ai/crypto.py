"""AI-only envelope key: offline analyzer never receives the connector key."""
import json
import os
from cryptography.fernet import Fernet
from peaso.auth.secrets import private_file


class AICipher:
    def __init__(self, identity_dir):
        key = os.getenv('PEASO_AI_ENCRYPTION_KEY')
        arn = os.getenv('PEASO_AI_CREDENTIAL_SECRET_ARN')
        if arn:
            import boto3
            key = boto3.client('secretsmanager').get_secret_value(SecretId=arn)['SecretString'].strip()
        if os.getenv('PEASO_STORAGE') == 'dynamodb' and not key:
            raise ValueError('AI envelope key is not configured')
        self.fernet = Fernet(key.encode() if key else private_file(identity_dir / 'ai' / 'credentials.key', Fernet.generate_key))

    def encrypt(self, value):
        return self.fernet.encrypt(json.dumps(value, separators=(',', ':')).encode()).decode()

    def decrypt(self, value):
        return json.loads(self.fernet.decrypt(value.encode()))
