import pickle


def load_model(path: str):
    with open(path, "rb") as fh:
        return pickle.loads(fh.read())
