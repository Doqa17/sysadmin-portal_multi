import sqlite3

def migrate():
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        print("Adding column ad_modify_mode to table ad_settings...")
        cursor.execute("ALTER TABLE ad_settings ADD COLUMN ad_modify_mode VARCHAR(20) DEFAULT 'auto'")
        conn.commit()
        conn.close()
        print("Column added successfully.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("Column already exists.")
        else:
            print(f"SQLite Error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    migrate()
