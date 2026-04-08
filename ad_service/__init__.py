# AD Service Package
# Modularized for better maintainability and performance

from .core import test_connection
from .auth import authenticate_ad
from .manage import (
    sync_users, toggle_ad_account, get_user_ad_info, 
    get_ad_containers, create_ad_user, delete_ad_user, update_ad_user_info
)
from .password import (
    change_ad_password, extend_ad_password, unlock_ad_account, 
    force_password_change, set_ad_password_never_expires
)
from .groups import (
    remove_user_from_group, search_ad_groups, add_user_to_group
)

# Exporting all public functions to maintain a single API entry point
__all__ = [
    'test_connection',
    'authenticate_ad',
    'sync_users',
    'toggle_ad_account',
    'get_user_ad_info',
    'get_ad_containers',
    'create_ad_user',
    'delete_ad_user',
    'update_ad_user_info',
    'change_ad_password',
    'extend_ad_password',
    'unlock_ad_account',
    'force_password_change',
    'set_ad_password_never_expires',
    'remove_user_from_group',
    'search_ad_groups',
    'add_user_to_group'
]
