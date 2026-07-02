# Static analysis sample only. Do not execute.

import requests

page_text = requests.get(url).text
prompt = f"Summarize this web page:\n\n{page_text}"

llm.invoke(prompt)
