"""Outside services: email notifications and the user directory.

Both have an AWS implementation (Amazon SES, Amazon Cognito) and a simple
in-memory one used for development and tests.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("qsign")


class Notifier:
    def __init__(self):
        self.sent: list[dict] = []

    def send(self, to: str, subject: str, body: str) -> None:
        self.sent.append({"to": to, "subject": subject, "body": body})
        log.info("notification to=%s subject=%s", to, subject)


class SesNotifier(Notifier):
    def __init__(self, sender: str):
        super().__init__()
        import boto3

        self.ses = boto3.client("sesv2")
        self.sender = sender

    def send(self, to, subject, body):
        try:
            self.ses.send_email(
                FromEmailAddress=self.sender,
                Destination={"ToAddresses": [to]},
                Content={"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}}},
            )
        except Exception:  # an email failure must not undo a signature
            log.exception("email to %s failed", to)


def notifier_from_env() -> Notifier:
    sender = os.environ.get("QSIGN_SES_SENDER")
    return SesNotifier(sender) if sender else Notifier()


class Directory:
    """Creates user accounts. Users are invited and set their own password."""

    def __init__(self):
        self.users: dict[str, dict] = {}

    def exists(self, email: str) -> bool:
        return email in self.users

    def invite(self, email: str, name: str, org_id: str, admin: bool = False) -> None:
        if email in self.users:
            raise ValueError(f"{email} already has an account")
        self.users[email] = {"email": email, "name": name, "org_id": org_id, "admin": admin}


class CognitoDirectory(Directory):
    def __init__(self, user_pool_id: str):
        super().__init__()
        import boto3

        self.cognito = boto3.client("cognito-idp")
        self.pool = user_pool_id

    def exists(self, email):
        try:
            self.cognito.admin_get_user(UserPoolId=self.pool, Username=email)
            return True
        except self.cognito.exceptions.UserNotFoundException:
            return False

    def invite(self, email, name, org_id, admin=False):
        try:
            self.cognito.admin_create_user(
                UserPoolId=self.pool,
                Username=email,
                UserAttributes=[
                    {"Name": "email", "Value": email},
                    {"Name": "email_verified", "Value": "true"},
                    {"Name": "name", "Value": name},
                    {"Name": "custom:org_id", "Value": org_id},
                ],
                DesiredDeliveryMediums=["EMAIL"],
            )
        except self.cognito.exceptions.UsernameExistsException as exc:
            raise ValueError(f"{email} already has an account") from exc
        if admin:
            self.cognito.admin_add_user_to_group(UserPoolId=self.pool, Username=email, GroupName="org-admin")


def directory_from_env() -> Directory:
    pool = os.environ.get("QSIGN_USER_POOL_ID")
    return CognitoDirectory(pool) if pool else Directory()
