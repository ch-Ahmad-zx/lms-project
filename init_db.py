import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            license_key TEXT,
            expiry_date TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("Database FIXED with expiry_date column.")

if __name__ == '__main__':
    init_db()