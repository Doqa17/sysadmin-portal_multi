from app_factory import create_app
from models import User, ADSettings
from ad_service import _get_ldap3, _get_connection

app = create_app()

with app.app_context():
    settings = ADSettings.query.first()
    if not settings:
        print("ERROR: ADSettings is None")
    elif not settings.is_active:
        print("ERROR: ADSettings is not active")
    else:
        print(f"Server: {settings.server}")
        print(f"Base DN: {settings.base_dn}")
        print(f"Bind User: {settings.bind_user}")
        
        conn, err = _get_connection(settings)
        if err:
            print(f"ERROR binding service account: {err}")
        else:
            print("SUCCESS: Service account bind worked.")
            
            users = User.query.filter_by(is_from_ad=True, is_active=True).all()
            print(f"Found {len(users)} active AD users in database.")
            
            ldap3 = _get_ldap3()
            for u in users:
                search_filter = f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(u.username)}))'
                print(f"Searching for: {u.username} with filter {search_filter}")
                conn.search(settings.base_dn, search_filter, attributes=['distinguishedName'])
                if conn.entries:
                    print(f"  -> Found DN: {conn.entries[0].distinguishedName}")
                else:
                    print(f"  -> ERROR: User {u.username} not found in AD!")
            
            conn.unbind()
