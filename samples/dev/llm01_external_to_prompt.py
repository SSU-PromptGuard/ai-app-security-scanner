# Static analysis sample only. Do not execute.

import requests

page = requests.get("https://example.com").text
llm.invoke(f"Summarize this page: {page}")
