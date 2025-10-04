
from functools import reduce


def number_to_rrns(number, moduli):
    
    return [number % m for m in moduli]


def rrns_to_number(residues, moduli):
  
    if len(residues) != len(moduli):
        raise ValueError("Lunghezza di resti e moduli non corrispondente")

    # Prodotto totale dei moduli con funziona lambda
    M = reduce(lambda a, b: a * b, moduli)

    result = 0

    for r_i, m_i in zip(residues, moduli):
        M_i = M // m_i  # Prodotto degli altri moduli
        # Inverso moltiplicativo di M_i modulo m_i
        inv_M_i = pow(M_i, -1, m_i)
        result += r_i * M_i * inv_M_i

    return result % M


