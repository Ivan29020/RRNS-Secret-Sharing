# main_rrns_refresh_shifted.py
from phe import paillier
import random
from rrns_utils import number_to_rrns, rrns_to_number
from general_utils import generate_rrns_moduli, format_encrypted_number, prod_of_subset, min_product_of_k
from itertools import combinations
from math import prod



def solutions_for_partial(partial_rems, partial_mods):
    x = rrns_to_number(partial_rems, partial_mods)
    modulus = prod(partial_mods)
    return x % modulus, modulus



# ====================================================================
# SETUP PARAMETRI
# ====================================================================

secret = random.randint(100000, 1000000)
t_threshold = 3
n_partecipants = 5
rnns_moduls = generate_rrns_moduli(
    count=n_partecipants,
    secret=secret,
    threshold_k=t_threshold
)
print("\n\n" + "="*12 + " SETUP DEL SISTEMA " + "="*12)
print(f"Segreto S: {secret}")
print(f"Moduli RRNS: {rnns_moduls}")

# ====================================================================
# GENERAZIONE CHIAVI PAILLIER
# ====================================================================
print("\n\n" + "="*12 + " GENERAZIONE CHIAVI PAILLIER " + "="*12)
public_key, private_key = paillier.generate_paillier_keypair()
print("Chiavi generate.")

# ====================================================================
# Conversione SEGRETO in RRNS
# ====================================================================
residues = number_to_rrns(secret, rnns_moduls)
print("\n\n" + "="*12 + " CONVERSIONE SEGRETO IN RRNS " + "="*12)
print(f"Il segreto {secret} è stato scomposto nei residui (modulo,residuo): \n\n{list(zip(rnns_moduls, residues))}")


# ====================================================================
#  Crittografia delle Share
# ====================================================================
all_plain_shares = [(i, residues[i]) for i in range(len(rnns_moduls))]
all_encrypted_shares = []
print("\n\n" + "="*12 + " CRITTOGRAFIA DELLE SHARE " + "="*12)
for (i, y) in all_plain_shares:
    enc_y = public_key.encrypt(y)
    all_encrypted_shares.append((i, enc_y))
print("Tutte le componenti y delle share sono state crittografate (paillier).")


# ====================================================================
# SIMULAZIONE DISTRIBUZIONE
# ====================================================================

participants = []
for idx, mod in enumerate(rnns_moduls):
    participants.append({
        "id": idx, "mod": mod,
        "residue_plain": residues[idx],
        "residue_enc": all_encrypted_shares[idx][1]
    })
print("\nDistribuzione alle parti completata.")
print("\n\n" + "="*20 + " SIMULAZIONE DISTRIBUZIONE  " + "="*20)
print(f"Creati {len(participants)} partecipanti.")
print(f"\nTutte le info del partecipante 2:")
print(f"  ID: {participants[1]['id']}")
print(f"  Modulo: {participants[1]['mod']}")
print(f"  Residuo in chiaro: {participants[1]['residue_plain']}")
print(f"  Share crittografata: {format_encrypted_number(participants[1]['residue_enc'])}")

# ====================================================================
#  SIMULAZIONE FURTO
# ====================================================================
stolen_idx = 0
stolen_participant = participants[stolen_idx]
stolen_mod = stolen_participant["mod"]
stolen_residue = stolen_participant["residue_plain"]
print("\n\n" + "="*20 + " SIMULAZIONE FURTO  " + "="*20)
print(f"Residuato rubato: partecipante {stolen_idx}, modulo {stolen_mod}, residuo {stolen_residue}")

# =================================================================================
# PROACTIVE REFRESH 
# =================================================================================
M_total = prod(rnns_moduls)
min_prod_t = min_product_of_k(rnns_moduls, t_threshold)
S_refreshed = random.randrange(0, min_prod_t)
K = (S_refreshed - secret) % M_total
enc_K_per_mod = [public_key.encrypt(K % m) for m in rnns_moduls]
for i in range(len(participants)):
    old_enc = participants[i]["residue_enc"]              # ciphertext esistente (Paillier)
    add_enc = enc_K_per_mod[i]                            # ciphertext di (K % m_i)
    new_enc = old_enc + add_enc
    participants[i]["residue_plain_new"] = private_key.decrypt(new_enc)
    participants[i]["residue_enc_new"] = new_enc
print("\n\n" + "="*12 + " PROACTIVE REFRESH (SHIFT DIRETTO) " + "="*12)
print(f"K (shift) calcolato =  {K}")
print("Nuovi residui generati shiftando i vecchi di K:")


print(f"\nTutte le nuove info del partecipante 2:")
print(f"  ID: {participants[1]['id']}")
print(f"  Modulo: {participants[1]['mod']}")
print(f"  Residuo in chiaro: {participants[1]['residue_plain_new']}")
print(f"  Share crittografata: {format_encrypted_number(participants[1]['residue_enc_new'])}")

# =================================================================================
# SCENARI DI ATTACCO / RICOSTRUZIONE 
# =================================================================================
print("\n\n" + "="*12 + " SCENARI DI ATTACCO / RICOSTRUZIONE " + "="*12)


# 1) Attaccante con vecchio residuo rubato + nuovi residui

print(f"\n1) Attaccante con vecchio residuo rubato + nuovi residui:")
auth_subset_attacker = [stolen_idx] + list(range(1, t_threshold))  
mods_subset_attacker = [participants[idx]["mod"] for idx in auth_subset_attacker]
rems_subset_attacker = []
for idx in auth_subset_attacker:
    if idx == stolen_idx:
        rems_subset_attacker.append(participants[idx]["residue_plain"])
    else:
        rems_subset_attacker.append(participants[idx]["residue_plain_new"])
reconstructed_S_attacker = rrns_to_number(rems_subset_attacker, mods_subset_attacker)

print(f"   Partecipanti: {auth_subset_attacker} (residuo {stolen_idx} è quello vecchio rubato)")
print(f"   Residui usati: {rems_subset_attacker}")
print(f"   Ricostruisce: {reconstructed_S_attacker}")
print(f"   Corrisponde a S? {reconstructed_S_attacker == secret}")
print(f"   Corrisponde a S'? {reconstructed_S_attacker == S_refreshed}")




# 2) Ricostruzione con t-1  nuovi residui 

auth_subset = list(range(t_threshold-1))
mods_subset = [participants[idx]["mod"] for idx in auth_subset]
rems_subset = [participants[idx]["residue_plain_new"] for idx in auth_subset]
reconstructed_S_partial = rrns_to_number(rems_subset, mods_subset)

print(f"\n3) Ricostruzione con t - 1 nuovi residui {auth_subset}:")
print("   Ricostruisce parzialmente S_refreshed =", reconstructed_S_partial)
print(f"   Corrisponde a S ? {reconstructed_S_partial==secret}")
print(f"   Corrisponde a S' ? {reconstructed_S_partial==S_refreshed}")



# 4) Autorizzati con t residui nuovi + K

auth_subset = random.sample(range(n_partecipants), t_threshold)
auth_mods = [participants[i]["mod"] for i in auth_subset]
auth_rems_new = [participants[i]["residue_plain_new"] for i in auth_subset]
reconstructed_S_refreshed_auth = rrns_to_number(auth_rems_new, auth_mods)
reconstructed_S_final = (reconstructed_S_refreshed_auth - K) % M_total

print(f"\n4) Ricostruzione con t autorizzati (indici {auth_subset}):")
print("   Ricostruiscono S_refreshed =", reconstructed_S_refreshed_auth)
print("   Sottraggono K -> S =", reconstructed_S_final)



# =================================================================================
# Verifica Finale
# =================================================================================
final_secret = reconstructed_S_final
print("\n" + "="*25 + " VERIFICA FINALE " + "="*25)
print(f"Segreto Originale: {secret}")
print(f"Segreto Ricostruito: {final_secret}")
print(f"Processo corretto? {secret == final_secret}")