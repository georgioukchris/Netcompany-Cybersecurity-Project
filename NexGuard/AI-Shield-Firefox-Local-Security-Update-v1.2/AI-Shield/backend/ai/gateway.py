from .gemini import generate_reply

SUPPORTED_PROVIDERS = {
    "gemini": {
        "name": "Google Gemini",
        "models": ["gemini-2.5-flash"],
    }
}

def chat(provider: str, model: str | None, messages: list[dict[str, str]]) -> str:
    provider = provider.lower().strip()
    if provider != "gemini":
        raise ValueError("Προς το παρόν υποστηρίζεται μόνο το Gemini.")
    if model and model not in SUPPORTED_PROVIDERS["gemini"]["models"]:
        raise ValueError("Μη υποστηριζόμενο μοντέλο.")
    return generate_reply(messages, model)
