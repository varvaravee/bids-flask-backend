import sqlite3

def droptable():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS users")
    conn.commit()
    conn.close()

    print("Users table has been dropped.")

#call function to drop table
droptable()