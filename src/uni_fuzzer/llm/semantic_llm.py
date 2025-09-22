import logging
from sentence_transformers import SentenceTransformer, util

from uni_fuzzer.core.utility import status

log = logging.getLogger(__name__)

def filterML(wordlistPath, prompt, similarityThreshold=0.25):
    """
        Filter a wordlist using semantic similarity to a prompt.
    """
    #Load wordlist
    try:
        with open(wordlistPath, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]

    except Exception:
        log.debug("filterML: failed to read wordlist from %s", wordlistPath, exc_info=True)
        status("[-] Failed to read wordlist")
        raise

    if not payloads:
        log.debug("filterML: no payloads found, returning empty list")
        return []

    # Load model ***subject to change***
    model = SentenceTransformer('all-MiniLM-L6-v2')

    # Prompt and payloads
    promptEnc = model.encode(prompt, convert_to_tensor=True)
    payloadEnc = model.encode(payloads, convert_to_tensor=True)

    # Compute similarity
    similarities = util.cos_sim(promptEnc, payloadEnc)[0]

    # Filter payloads
    filtered = [payloads[i] for i in range(len(payloads)) if similarities[i] > similarityThreshold]

    return filtered