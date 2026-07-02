# Static analysis sample only. Do not execute.

from transformers import AutoModel

model = AutoModel.from_pretrained(
    model_name,
    trust_remote_code=True
)
