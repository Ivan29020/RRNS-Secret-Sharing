import os
import time
import random
from math import prod
from phe import paillier
from rrns_utils import number_to_rrns, rrns_to_number
from general_utils import generate_rrns_moduli, min_product_of_k

# ================================================================
# Utility per test scalabilità
# ================================================================
def text_to_secrets(text):
    return [ord(char) for char in text]

def secrets_to_text(secrets):
    return ''.join([chr(num) for num in secrets])

def solutions_for_partial(partial_rems, partial_mods):
    x = rrns_to_number(partial_rems, partial_mods)
    modulus = prod(partial_mods)
    return x % modulus, modulus

# ================================================================
# Parametri Globali
# ================================================================
t_threshold = 3
n_partecipants = 5

# ================================================================
# Funzione principale: Split + Merge con timing
# ================================================================
def process_file(filename):
    print("\n" + "="*40)
    print(f"Analisi file: {filename}")
    print("="*40)

    # Lettura file
    input_text = open(filename, 'r').read()
    secrets = text_to_secrets(input_text)

    # Setup moduli
    max_secret = max(secrets)
    virtual_secret = max_secret * 1000
    rnns_moduls = generate_rrns_moduli(
        count=n_partecipants,
        secret=virtual_secret,
        threshold_k=t_threshold
    )

    # Generazione chiavi Paillier
    public_key, private_key = paillier.generate_paillier_keypair()

    # ================================================================
    # SPLIT (conversione in RRNS + crittografia share)
    # ================================================================
    start_split = time.perf_counter()

    all_residues = [number_to_rrns(secret, rnns_moduls) for secret in secrets]
    all_encrypted_shares = []
    for residues in all_residues:
        encrypted_shares = []
        for i, residue in enumerate(residues):
            enc_y = public_key.encrypt(residue)
            encrypted_shares.append((i, enc_y))
        all_encrypted_shares.append(encrypted_shares)

    participants = []
    for idx, mod in enumerate(rnns_moduls):
        participant = {
            "id": idx,
            "mod": mod,
            "residues_plain": [all_residues[s][idx] for s in range(len(secrets))],
            "residues_enc": [all_encrypted_shares[s][idx][1] for s in range(len(secrets))]
        }
        participants.append(participant)

    end_split = time.perf_counter()

    # ================================================================
    # MERGE (ricostruzione)
    # ================================================================
    start_merge = time.perf_counter()

    auth_subset = list(range(t_threshold))
    auth_mods = [participants[i]["mod"] for i in auth_subset]

    reconstructed_secrets = []
    for secret_idx in range(len(secrets)):
        rems_subset = [participants[i]["residues_plain"][secret_idx] for i in auth_subset]
        reconstructed_S = rrns_to_number(rems_subset, auth_mods)
        reconstructed_secrets.append(reconstructed_S)

    reconstructed_text = secrets_to_text(reconstructed_secrets)

    end_merge = time.perf_counter()

    # ================================================================
    # Report
    # ================================================================
    print(f"Dimensione file: {len(input_text)} caratteri")
    print(f"Tempo Split (s): {end_split - start_split:.4f}")
    print(f"Tempo Merge (s): {end_merge - start_merge:.4f}")
    print(f"Corretto? {reconstructed_text == input_text}")


# ================================================================
# MAIN - creazione file test e analisi
# ================================================================
if __name__ == "__main__":
    # Creiamo file di test con dimensioni diverse
    sizes = {
        "10B.txt": 10,
        "1kB.txt": 1024,
        "1MB.txt": 1024*1024
    }

    for fname, size in sizes.items():
        if not os.path.exists(fname):
            with open(fname, "w") as f:
                f.write("A" * size)  # contenuto semplice

    # Lanciamo l’analisi per ciascun file
    for fname in sizes.keys():
        process_file(fname)
