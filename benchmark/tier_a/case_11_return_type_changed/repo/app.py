from db_query_engine import execute_query

def fetch_rows(sql: str):
    data = execute_query(sql)
    return data["rows"]
