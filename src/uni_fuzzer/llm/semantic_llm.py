from sentence_transformers import SentenceTransformer, util

def filterML(wordlistPath, prompt, similarityThreshold=0.25):
    """
        Filter a wordlist using semantic similarity to a prompt.
    """
    #Load wordlist
    try:
        with open(wordlistPath, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]

    except Exception as e:
        raise RuntimeError(f"[-] Failed to read wordlist from {wordlistPath}: {e}")

    if not payloads:
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