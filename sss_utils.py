import random
""" Crea n shares usando Shamir's Secret Sharing su un polinomio casuale di grado t - 1. """
def create_shares(secret, t_threshold, n_share, mod):
    
    if secret >= mod:
        raise ValueError("Il segreto deve essere minore del modulo primo.")

    coefficients = [secret]
    for _ in range(t_threshold - 1):
        coefficients.append(random.randint(0, mod - 1))

    def evaluate_polynomial(x):
        y = 0
        for i, coeff in enumerate(coefficients):
            y = (y + coeff * pow(x, i, mod)) % mod
        return y

    shares = []
    for x in range(1, n_share + 1):
        y = evaluate_polynomial(x)
        shares.append((x, y))
    return shares

"""Ricostruisce il segreto da almeno t share usando interpolazione di Lagrange per x=0."""

def reconstruct_from_shares(shares, mod):
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        numerator = 1
        denominator = 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                numerator = (numerator * (-xm)) % mod
                denominator = (denominator * (xj - xm)) % mod
        lagrange_coefficient = numerator * pow(denominator, -1, mod)
        secret = (secret + yj * lagrange_coefficient) % mod

    return secret


