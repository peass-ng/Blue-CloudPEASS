"""Metadata-only Directory login read contract; no collector or registry imports."""
KIND = 'workspace_user_activity'
FIELDS = 'id,customerId,primaryEmail,suspended,archived,creationTime,lastLoginTime'
USERS = 'https://admin.googleapis.com/admin/directory/v1/users'
