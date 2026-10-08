#!/usr/bin/env bash
# Create the first administrator of a new organisation in QSign.
# Usage: scripts/create-org-admin.sh <stack-name> <org-id> <email> "<Full Name>"
# The person receives an email with a temporary password. On first sign-in they
# choose a new password and set up an authenticator app (MFA is required).
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: $0 <stack-name> <org-id> <email> \"<Full Name>\"" >&2
  exit 2
fi
STACK="$1"; ORG="$2"; EMAIL="$3"; NAME="$4"

if ! [[ "$ORG" =~ ^[a-z0-9][a-z0-9-]{1,62}$ ]] || [ "$ORG" = "guest" ]; then
  echo "org-id must be 2-63 lowercase letters, digits or dashes, and not 'guest'" >&2
  exit 2
fi

POOL=$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)

aws cognito-idp admin-create-user --user-pool-id "$POOL" --username "$EMAIL" \
  --user-attributes Name=email,Value="$EMAIL" Name=email_verified,Value=true \
                    Name=name,Value="$NAME" Name=custom:org_id,Value="$ORG" \
  --desired-delivery-mediums EMAIL >/dev/null
aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" --username "$EMAIL" --group-name org-admin

echo "Created $EMAIL as administrator of organisation '$ORG'."
