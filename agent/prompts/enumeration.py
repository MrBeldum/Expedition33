PROMPT = """Phase: enumeration.
Goal: enumerate discovered services deeply enough to rank attack vectors. For web services, fingerprint with whatweb/curl and only run directory or vhost fuzzing when there is a concrete web target. For versioned services, use searchsploit to identify plausible public issues, but verify manually before exploitation.
"""
