# context_profiles.py
CONTEXT_PROFILES = {
    "small": {
        "max_contextual_docs": 2,
        "contextual_detail": "compact",
    },
    "medium": {
        "max_contextual_docs": 4,
        "contextual_detail": "summary",  # futuro
    },
    "large": {
        "max_contextual_docs": 8,
        "contextual_detail": "full",
    },
}

def get_context_profile(name: str):
    return CONTEXT_PROFILES.get(
        name,
        CONTEXT_PROFILES["small"]
    )
