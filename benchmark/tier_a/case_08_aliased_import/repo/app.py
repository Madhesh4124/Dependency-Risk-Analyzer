import logger_engine as log

def record_critical_incident(message: str) -> str:
    """Uses aliased import `log` to call removed function `log_fatal`."""
    return log.log_fatal(message)

