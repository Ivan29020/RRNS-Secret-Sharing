import random
import sympy
from phe import paillier
from itertools import combinations
from math import prod


def check_threshold_property(moduli, secret, threshold_k):
    """
    Verifica la proprietà soglia:
      - per ogni sottoinsieme S con |S| < threshold_k: prod(S) <= secret
      - per ogni sottoinsieme S con |S| >= threshold_k: prod(S) > secret
    """
    n = len(moduli)
    for r in range(1, n + 1):
        for comb in combinations(moduli, r):
            p = prod(comb)
            if r < threshold_k:
                if p > secret:
                    return False
            else:
                if p <= secret:
                    return False
    return True


def generate_rrns_moduli(count=3, min_mod=2, start_max=30, step=20, secret=None, threshold_k=3):
    """
    Genera automaticamente moduli RRNS che rispettino la proprietà soglia.
    - count: quanti moduli generare
    - threshold_k: soglia minima di moduli per ricostruire il segreto
    - secret: il segreto da proteggere
    - min_mod/start_max: intervallo iniziale di ricerca
    - step: quanto aumentare max_mod se non si trova una soluzione
    """
    if secret is None:
        raise ValueError("Devi passare il segreto per garantire la proprietà soglia.")
    if threshold_k < 2 or threshold_k > count:
        raise ValueError("threshold_k deve essere tra 2 e count")

    max_mod = start_max
    while True:
        candidates = list(sympy.primerange(min_mod, max_mod))
        if len(candidates) < count:
            max_mod += step
            continue

        for _ in range(2000):
            chosen = random.sample(candidates, count)
            if check_threshold_property(chosen, secret, threshold_k):
                return sorted(chosen)

        # nessuna soluzione → allarghiamo intervallo
        max_mod += step


def generate_prime_for_sss(rrns_moduli, max_prime=500, secret=None):
    """
    Genera un primo per lo schema SSS tale che sia maggiore di max(rrns_moduli) e del segreto.
    """
    lower_bound = max(rrns_moduli) + 1
    if secret is not None:
        lower_bound = max(lower_bound, secret + 1)
    return sympy.randprime(lower_bound, max_prime)


def format_encrypted_number(enc_num: paillier.EncryptedNumber) -> str:
    
    ciphertext_val = enc_num.ciphertext()
    ciphertext_str = str(ciphertext_val)

    if len(ciphertext_str) > 30:
        return f"{ciphertext_str[:15]}...{ciphertext_str[-15:]}"
    else:
        return ciphertext_str

def prod_of_subset(moduli_subset):
    p = 1
    for m in moduli_subset:
        p *= m
    return p

def min_product_of_k(moduli, k):
    return min(prod(comb) for comb in combinations(moduli, k))

