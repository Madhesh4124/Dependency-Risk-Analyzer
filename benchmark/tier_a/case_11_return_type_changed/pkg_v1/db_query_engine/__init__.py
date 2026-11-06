"""Mock dependency db_query_engine v1.0.0"""
__version__ = "1.0.0"

def execute_query(sql: str):
    return {"rows": ["item1", "item2"], "count": 2}
