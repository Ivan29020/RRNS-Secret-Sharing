from phe import paillier
import random 
from rrns_utils import number_to_rrns, rrns_to_number
from sss_utils import create_shares, reconstruct_from_shares 
from acca import generate_rrns_moduli, generate_prime_for_sss, format_encrypted_number


# ====================================================================
# SETUP PARAMETRI
# ====================================================================

secret = random.randint(100000,1000000)
#t_threshold = 3
#n_partecipants = 5
#k_moduli = 3
#rnns_moduls = generate_rrns_moduli(n_partecipants, min_mod=1, max_mod=23, secret=secret)
# Genera moduli RRNS tali che servano almeno t_threshold partecipanti per ricostruire
#rnns_moduls = generate_rrns_moduli(
 #   count=k_moduli,      # numero moduli RRNS da usare (es. k_moduli)
  #  min_mod=11,
   # max_mod=200,         # aumenta se necessario
    #secret=secret,
    #threshold_k=t_threshold
#)
#primo_sss = generate_prime_for_sss(rnns_moduls, max_prime=500, secret=secret)
#rnns_moduls = [11, 13, 17]  
#primo_sss = 257  


# ====================================================================
# SETUP PARAMETRI
# ====================================================================


t_threshold = 3
n_partecipants = 5

# Generazione automatica dei moduli RRNS con proprietà soglia
rnns_moduls = generate_rrns_moduli(
    count=n_partecipants,
    secret=secret,
    threshold_k=t_threshold
)
primo_sss = generate_prime_for_sss(rnns_moduls, max_prime=500000000, secret=secret)







print("\n\n" + "="*20 + " SETUP DEL SISTEMA " + "="*20)
print(f"Segreto S: {secret}")
print(f"Moduli RRNS: {rnns_moduls}")
print(f"Schema SSS: ({t_threshold}, {n_partecipants}) su Galois Field({primo_sss})")

# ====================================================================
# GENERAZIONE CHIAVI PAILLIER
# ====================================================================
print("\n\n" + "="*20 + " GENERAZIONE CHIAVI PAILLIER  " + "="*20)
public_key, private_key = paillier.generate_paillier_keypair()
print("Chiavi generate.")

# ====================================================================
# Conversione SEGRETO in RRNS
# ====================================================================
residues = number_to_rrns(secret, rnns_moduls)
print("\n\n" + "="*20 + " CONVERSIONE SEGRETO IN RRNS  " + "="*20)
print(f"Il segreto {secret} è stato scomposto nei residui: {residues}")


# ====================================================================
# Shamir's Secret Sharing per ogni residuo
# ====================================================================
all_plain_shares = []
print("\n\n" + "="*20 + " SHAMIR SECRET SHARING  " + "="*20)
for i, r_i in enumerate(residues):
    print(f"Condivisione del residuo {i+1} (valore={r_i})...")
    shares_for_residues = create_shares(r_i, t_threshold, n_partecipants, primo_sss)
    all_plain_shares.append(shares_for_residues)
print(f"\nEsempio share : \n{all_plain_shares[0]}")

# ====================================================================
#  Crittografia delle Share
# ====================================================================
all_encrypted_shares = []
print("\n\n" + "="*20 + " CRITTOGRAFIA DELLE SHARE  " + "="*20)
for shares_for_residues in all_plain_shares:
    encrypted_shares = []
    for x, y in shares_for_residues:
        encrypted_y = public_key.encrypt(y)
        encrypted_shares.append((x, encrypted_y))
    all_encrypted_shares.append(encrypted_shares)
print("Tutte le componenti y delle share sono state crittografate.")


# ====================================================================
# SIMULAZIONE DISTRIBUZIONE
# ====================================================================
partecipants = [[] for _ in range(n_partecipants)]
for shares_crittografate_per_residuo in all_encrypted_shares:
    for i, (x, enc_y) in enumerate(shares_crittografate_per_residuo):
        partecipants[i].append((x, enc_y))

print("\n\n" + "="*20 + " SIMULAZIONE DISTRIBUZIONE  " + "="*20)
print(f"Creati {len(partecipants)} partecipanti.")
print(f"Il partecipante 1 possiede {len(partecipants[0])} share crittografate (una per ogni residuo RRNS).\n")
for i, share in enumerate(partecipants[0]):
    x, encrypted_y = share
    print(f"Share per residuo {i+1}: {x}, {format_encrypted_number(encrypted_y)}")

# ====================================================================
# PROACTIVE REFRESH 
# ====================================================================
print("\n\n" + "="*20 + " PROACTIVE REFRESH  " + "="*20)

# Generazione set di "zero-shares" per questo round di refresh

all_zero_shares_sets = []
for i in range(len(residues)):
    zero_shares_for_residues = create_shares(0, t_threshold, n_partecipants, primo_sss)
    all_zero_shares_sets.append(zero_shares_for_residues)
print(f"Generate {len(all_zero_shares_sets)} set di 'zero-shares' per il refresh globale.")

# Crittografia di  tutte le zero-shares prima della distribuzione
all_zero_shares_encrypted = []
for zero_shares_set in all_zero_shares_sets:
    encrypted_set = [(x, public_key.encrypt(y)) for x, y in zero_shares_set]
    all_zero_shares_encrypted.append(encrypted_set)
print("Tutte le zero-shares sono state crittografate.")

# Aggiornamento omomorfico per ogni partecipante
print("\nRefresh delle share per tutti i partecipanti...")
for id_p in range(n_partecipants):
    updated_shares = []
    for i in range(len(residues)):
        old_x, old_encrypted_y = partecipants[id_p][i]
        x_zero, zero_encrypted_y = all_zero_shares_encrypted[i][id_p]
        new_encrypted_y = old_encrypted_y + zero_encrypted_y
        updated_shares.append((old_x, new_encrypted_y))
        if id_p == 0 and i == 0:
            esempio_vecchia_share = (old_x, old_encrypted_y)
            esempio_zero_share = (x_zero, zero_encrypted_y)
            print("\n--- Esempio di Refresh per il Partecipante 1, primo residuo ---")
            print(f"  Vecchia Share          : {old_x}, {format_encrypted_number(old_encrypted_y)}")
            print(f"  Share 'Zero' sommata   : {x_zero}, {format_encrypted_number(zero_encrypted_y)}")
            print(f"  Nuova Share (risultato): {old_x}, {format_encrypted_number(new_encrypted_y)}")
            print("------------------------------------------------------------")
    
    partecipants[id_p] = updated_shares
print("Tutti i partecipanti hanno rinfrescato le loro share.")


# ====================================================================
# RICOSTRUZIONE FINALE 
# ====================================================================

print("\n" + "="*20 + " RICOSTRUZIONE FINALE " + "="*20)
# Gruppo di collaboratori (almeno t_threshold)
collaborators = random.sample(range(n_partecipants), t_threshold)
print(f"\n--- Ricostruzione con i partecipanti: {', '.join(str(i+1) for i in collaborators)} ---")
if len(collaborators) < t_threshold:
    raise ValueError("Non ci sono abbastanza partecipanti per la ricostruzione!")

# Creazione dizionario delle share necessarie, raggruppandole per residuo
shares_for_reconstruction_for_residue = {i: [] for i in range(len(rnns_moduls))}

for c in collaborators:
    # Prendiamo le share del partecipante
    c_shares = partecipants[c]
    for i, (x, enc_y) in enumerate(c_shares):
        y = private_key.decrypt(enc_y) % primo_sss
        shares_for_reconstruction_for_residue[i].append((x, y))

print("Share raccolte dai collaboratori, decriptate e corrette con il modulo.")

# ====================================
# RICOSTRUZIONE PARZIALE con k moduli
# ====================================

k_moduli = t_threshold  
selected_indices = random.sample(range(len(rnns_moduls)),k_moduli)

print(f"\n--- Ricostruzione usando solo {k_moduli} moduli ---")
print(f"Indici scelti: {selected_indices}")

reconstructed_residues = []
selected_moduli = []

for i in selected_indices:
    reconstructed_residue = reconstruct_from_shares(shares_for_reconstruction_for_residue[i], primo_sss)
    reconstructed_residues.append(reconstructed_residue)
    selected_moduli.append(rnns_moduls[i])
    print(f"Residuo {i+1} ricostruito: {reconstructed_residue} (Originale: {residues[i]})")

print("\n--- Ricostruzione del segreto finale via RRNS (CRT) con subset di moduli ---")
final_secret = rrns_to_number(reconstructed_residues, selected_moduli)

# VERIFICA FINALE
print("\n" + "="*25 + " VERIFICA FINALE " + "="*25)
print(f"Segreto Originale: {secret}")
print(f"Segreto Ricostruito: {final_secret}")
print(f"\nL'intero processo ha funzionato? {secret == final_secret}")

