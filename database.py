import sqlite3


DATABASE = "scanner.db"


def create_database():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            risk TEXT,
            description TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_result(result, vulnerability):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans
        (
            host,
            port,
            protocol,
            state,
            service,
            product,
            version,
            risk,
            description
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result["host"],
        result["port"],
        result["protocol"],
        result["state"],
        result["service"],
        result["product"],
        result["version"],
        vulnerability["risk"],
        vulnerability["description"]
    ))

    conn.commit()
    conn.close()


def get_results():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """)

    results = cursor.fetchall()

    conn.close()

    return results