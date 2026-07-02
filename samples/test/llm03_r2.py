from transformers import AutoModel


def load_model(repo_id: str):
    return AutoModel.from_pretrained(repo_id, trust_remote_code=True)
