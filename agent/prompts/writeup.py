WRITEUP_PROMPT = """Generate a beginner-friendly HackTheBox writeup in markdown from the complete Expedition33 session log and structured context.

Requirements:
- Plain English for readers with basic Linux knowledge and limited HTB experience.
- Explain what each significant command accomplished and why it was run.
- Include significant commands and actual output snippets, truncated where necessary.
- Explain vulnerabilities in plain terms.
- Use a linear narrative: Enumeration -> Foothold -> Privilege Escalation -> Flags.
- Briefly mention dead ends so the decision-making is understandable.
- End with a Key Takeaways section.
Return markdown only.
"""
