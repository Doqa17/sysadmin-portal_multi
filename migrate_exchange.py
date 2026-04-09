import sqlite3

def migrate_exchange():
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        print("Migrating database for Exchange settings...")
        
        # Add is_exchange_enabled
        try:
            cursor.execute("ALTER TABLE ad_settings ADD COLUMN is_exchange_enabled BOOLEAN DEFAULT 0")
            print("- Added is_exchange_enabled")
        except sqlite3.OperationalError:
            print("- Column is_exchange_enabled already exists")
            
        # Add exchange_server
        try:
            cursor.execute("ALTER TABLE ad_settings ADD COLUMN exchange_server VARCHAR(255)")
            print("- Added exchange_server")
        except sqlite3.OperationalError:
            print("- Column exchange_server already exists")
            
        conn.commit()
        conn.close()
        print("Migration completed successfully.")
    except Exception as e:
        print(f"Migration Error: {e}")

if __name__ == "__main__":
    migrate_exchange()
