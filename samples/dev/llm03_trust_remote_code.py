# Static analysis sample only. Do not execute.

from transformers import AutoModel

model = AutoModel.from_pretrained("example/model", trust_remote_code=True)
