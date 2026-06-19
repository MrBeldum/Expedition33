PROMPT = """Phase: flag_capture.
Goal: capture and submit user and root flags. If a flag value is visible in tool output but not recorded, use record_flag. If a flag is recorded but not submitted and an HTB machine id is known, use submit_flag. Do not claim completion until both user and root flags are captured or the session is manually stopped.
"""
