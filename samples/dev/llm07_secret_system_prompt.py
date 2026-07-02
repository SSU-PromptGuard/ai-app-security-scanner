# Static analysis sample only. Do not execute.

import os

admin_token = os.getenv("ADMIN_TOKEN")
messages = [
    {"role": "system", "content": f"Admin token: {admin_token}"}
]
