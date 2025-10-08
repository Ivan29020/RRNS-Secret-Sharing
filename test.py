from phe import paillier
import random
from rrns_utils import number_to_rrns, rrns_to_number
from general_utils import generate_rrns_moduli, min_product_of_k
from math import prod, log2, ceil
import time
import matplotlib.pyplot as plt
import numpy as np
import sys
from threading import Thread


def calculate_optimal_block_size(moduli, paillier_key_bits):
    """
    Calcola la dimensione ottimale del blocco considerando:
    1. Il modulo Paillier deve essere > del massimo valore delle share RRNS
    2. Bilanciamento tra riduzione operazioni e overhead
    
    STRATEGIA: Usa blocchi piccoli (2-4 char) per massimizzare velocità
    """
    # Massimo valore rappresentabile con i moduli RRNS
    max_rrns_value = max(moduli)
    
    # Bit disponibili nel modulo Paillier (con margine di sicurezza del 30%)
    paillier_n_bits = paillier_key_bits
    safety_bits = int(paillier_n_bits * 0.7)  # margine conservativo
    
    # Per blocchi ASCII/UTF-8: ogni char ~ 8 bit (256 valori)
    # Un blocco di n caratteri: max_value = 256^n
    
    # Calcola quanti caratteri possiamo mettere mantenendo sicurezza
    # Vincolo: 256^n < max(moduli) E 256^n << 2^safety_bits
    
    max_chars_from_rrns = int(log2(max_rrns_value) / 8)  # Da moduli RRNS
    max_chars_from_paillier = int(safety_bits / 8)  # Da chiavi Paillier
    
    # Prendi il minimo e limita a 2-4 caratteri per bilanciare velocità
    optimal_chars = min(max_chars_from_rrns, max_chars_from_paillier, 4)
    optimal_chars = max(2, optimal_chars)  # Minimo 2 caratteri
    
    # Verifica finale
    max_block_value = (256 ** optimal_chars)
    if max_block_value >= max_rrns_value:
        optimal_chars = max(1, optimal_chars - 1)
    
    return optimal_chars


def text_to_blocks(text, block_size):
    """
    Converte un testo in blocchi di dimensione fissa.
    Ogni blocco diventa un singolo numero intero.
    """
    blocks = []
    
    for i in range(0, len(text), block_size):
        block_text = text[i:i+block_size]
        # Converte il blocco in un numero intero usando encoding semplice
        block_num = 0
        for j, char in enumerate(block_text):
            block_num += ord(char) * (256 ** j)
        
        blocks.append((block_num, len(block_text)))
    
    return blocks


def blocks_to_text(blocks):
    """
    Converte una lista di blocchi numerici in testo.
    """
    text_parts = []
    
    for block_num, original_length in blocks:
        # Decodifica il numero in caratteri
        chars = []
        temp_num = block_num
        for _ in range(original_length):
            chars.append(chr(temp_num % 256))
            temp_num //= 256
        
        text_parts.append(''.join(chars))
    
    return ''.join(text_parts)


def validate_paillier_modulus(max_secret_value, moduli, public_key):
    """
    Verifica che il modulo n di Paillier sia sufficientemente grande.
    VINCOLO CRITICO: n > max(share_RRNS_value)
    """
    max_rrns_share = max(moduli)
    paillier_n = public_key.n
    
    if paillier_n <= max_rrns_share:
        raise ValueError(
            f"ERRORE CRITICO: Modulo Paillier troppo piccolo!\n"
            f"  Modulo Paillier n = {paillier_n}\n"
            f"  Max modulo RRNS = {max_rrns_share}\n"
            f"  Richiesto: n > {max_rrns_share}\n"
            f"  Aumentare n_length nella generazione chiavi Paillier!"
        )
    
    safety_margin = (paillier_n / max_rrns_share)
    
    if safety_margin < 2:
        print(f"  ⚠️  AVVISO: Margine di sicurezza basso ({safety_margin:.2f}x)")
    else:
        print(f"  ✓ Margine di sicurezza Paillier: {safety_margin:.2f}x")
    
    return True


def homomorphic_crt(encrypted_residues, moduli, M_total, public_key):
    """
    Chinese Remainder Theorem HOMOMORPHICO.
    Ricostruisce un numero da residui CIFRATI senza mai decrittarli.
    """
    encrypted_result = public_key.encrypt(0)
    
    for i, (enc_residue, mod) in enumerate(zip(encrypted_residues, moduli)):
        M_i = M_total // mod
        y_i = pow(M_i, -1, mod)
        coeff = (M_i * y_i) % M_total
        encrypted_term = enc_residue * coeff
        encrypted_result = encrypted_result + encrypted_term
    
    return encrypted_result


def generate_test_file(size_bytes):
    """Genera un contenuto di test di dimensione specifica"""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,!?\n"
    content = ''.join(random.choice(chars) for _ in range(size_bytes))
    return content


class ProgressBar:
    """Barra di progresso grafica con percentuale"""
    def __init__(self, total, desc="Progress", width=40):
        self.total = total
        self.current = 0
        self.desc = desc
        self.width = width
        self.start_time = time.time()
        
    def update(self, amount=1):
        """Aggiorna il progresso"""
        self.current += amount
        self._display()
    
    def _display(self):
        """Mostra la barra di progresso"""
        percent = (self.current / self.total) * 100
        filled = int(self.width * self.current / self.total)
        bar = '█' * filled + '░' * (self.width - filled)
        elapsed = time.time() - self.start_time
        
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"ETA: {eta:.1f}s"
        else:
            eta_str = "ETA: --"
        
        sys.stdout.write(f'\r{self.desc}: |{bar}| {percent:.1f}% ({self.current}/{self.total}) {eta_str} ')
        sys.stdout.flush()
        
        if self.current >= self.total:
            sys.stdout.write('\n')
            sys.stdout.flush()
    
    def finish(self):
        """Completa la barra"""
        self.current = self.total
        self._display()


class Loader:
    """Loader semplice per operazioni senza conteggio"""
    def __init__(self, desc="Loading", end="Done", timeout=0.1):
        self.desc = desc
        self.end = end
        self.timeout = timeout
        self._thread = None
        self.running = False
        self.spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        
    def _animate(self):
        idx = 0
        while self.running:
            sys.stdout.write(f'\r{self.desc} {self.spinner[idx % len(self.spinner)]} ')
            sys.stdout.flush()
            idx += 1
            time.sleep(self.timeout)
    
    def __enter__(self):
        self.running = True
        self._thread = Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self._thread:
            self._thread.join()
        sys.stdout.write(f'\r{self.desc} {self.end}\n')
        sys.stdout.flush()


def run_secret_sharing_test(input_text, t_threshold=3, n_partecipants=5, show_progress=True):
    """
    Esegue il processo completo di secret sharing e misura i tempi.
    VERSIONE OTTIMIZZATA A BLOCCHI - mantiene 256 bit per velocità.
    """
    timings = {}
    
    # ====================================================================
    # CONFIGURAZIONE INIZIALE - 256 bit per velocità massima
    # ====================================================================
    split_start = time.time()
    
    paillier_key_bits = 256  # MANTENIAMO 256 bit per velocità!
    
    if show_progress:
        print("  → Analisi dimensione input...")
    
    # Stima valore massimo conservativa
    estimated_max = 1000000  # Per caratteri singoli
    
    # Generazione moduli RRNS più piccoli e bilanciati
    if show_progress:
        with Loader(desc="  → Generazione moduli RRNS", end="✓"):
            rnns_moduls = generate_rrns_moduli(
                count=n_partecipants,
                secret=estimated_max,
                threshold_k=t_threshold
            )
    else:
        rnns_moduls = generate_rrns_moduli(
            count=n_partecipants,
            secret=estimated_max,
            threshold_k=t_threshold
        )
    
    # Chiavi Paillier 256 bit (VELOCITÀ MASSIMA)
    if show_progress:
        with Loader(desc=f"  → Generazione chiavi Paillier ({paillier_key_bits} bit)", end="✓"):
            public_key, private_key = paillier.generate_paillier_keypair(n_length=paillier_key_bits)
    else:
        public_key, private_key = paillier.generate_paillier_keypair(n_length=paillier_key_bits)
    
    # Calcola dimensione ottimale del blocco
    optimal_block_size = calculate_optimal_block_size(rnns_moduls, paillier_key_bits)
    
    if show_progress:
        print(f"  ✓ Dimensione blocco ottimale: {optimal_block_size} caratteri/blocco")
        print(f"    (Riduzione operazioni: {optimal_block_size}x)")
    
    # ====================================================================
    # SPLIT PHASE - Ottimizzato a blocchi
    # ====================================================================
    
    if show_progress:
        print(f"  → Conversione testo in blocchi ({optimal_block_size} char/block)...", end=' ', flush=True)
    
    blocks = text_to_blocks(input_text, optimal_block_size)
    num_blocks = len(blocks)
    
    if show_progress:
        print(f"✓ ({num_blocks} blocchi)")
        print(f"    Riduzione: {len(input_text)} caratteri → {num_blocks} blocchi")
    
    # Validazione vincolo Paillier
    max_block_value = max(b[0] for b in blocks)
    
    if show_progress:
        print(f"  → Validazione vincoli crittografici...")
    
    try:
        validate_paillier_modulus(max_block_value, rnns_moduls, public_key)
    except ValueError as e:
        print(f"\n{e}")
        return None, False
    
    # Conversione BLOCCHI in RRNS
    if show_progress:
        print(f"  → Conversione {num_blocks} blocchi in RRNS")
        pbar = ProgressBar(num_blocks, desc="    RRNS", width=50)
        all_residues = []
        for block_num, _ in blocks:
            all_residues.append(number_to_rrns(block_num, rnns_moduls))
            pbar.update(1)
    else:
        all_residues = [number_to_rrns(block_num, rnns_moduls) for block_num, _ in blocks]
    
    # Crittografia delle Share
    if show_progress:
        print(f"  → Crittografia di {num_blocks} share (blocchi)")
        pbar = ProgressBar(num_blocks, desc="    Encrypt", width=50)
        all_encrypted_shares = []
        for residues in all_residues:
            encrypted = [(i, public_key.encrypt(residue)) for i, residue in enumerate(residues)]
            all_encrypted_shares.append(encrypted)
            pbar.update(1)
    else:
        all_encrypted_shares = [
            [(i, public_key.encrypt(residue)) for i, residue in enumerate(residues)]
            for residues in all_residues
        ]
    
    # Distribuzione ai partecipanti
    if show_progress:
        print(f"  → Distribuzione a {n_partecipants} partecipanti...", end=' ', flush=True)
    participants = [
        {
            "id": idx,
            "mod": rnns_moduls[idx],
            "residues_enc": [all_encrypted_shares[s][idx][1] for s in range(num_blocks)]
        }
        for idx in range(n_partecipants)
    ]
    if show_progress:
        print("✓")
    
    # Proactive Refresh
    if show_progress:
        print("  → Pre-generazione K values...", end=' ', flush=True)
    M_total = prod(rnns_moduls)
    min_prod_t = min_product_of_k(rnns_moduls, t_threshold)
    
    K_values = [
        (random.randrange(0, min_prod_t) - block_num) % M_total 
        for block_num, _ in blocks
    ]
    if show_progress:
        print("✓")
    
    # Refresh delle share con operazioni homomorfiche
    if show_progress:
        print(f"  → Refresh proattivo delle share ({n_partecipants} partecipanti)")
        total_ops = n_partecipants * num_blocks
        pbar = ProgressBar(total_ops, desc="    Refresh", width=50)
        
        for participant in participants:
            mod = participant["mod"]
            participant["residues_enc_new"] = []
            
            for block_idx, K in enumerate(K_values):
                old_enc = participant["residues_enc"][block_idx]
                enc_K = public_key.encrypt(K % mod)
                new_enc = old_enc + enc_K
                participant["residues_enc_new"].append(new_enc)
                pbar.update(1)
    else:
        for participant in participants:
            mod = participant["mod"]
            participant["residues_enc_new"] = []
            
            for block_idx, K in enumerate(K_values):
                old_enc = participant["residues_enc"][block_idx]
                enc_K = public_key.encrypt(K % mod)
                new_enc = old_enc + enc_K
                participant["residues_enc_new"].append(new_enc)
    
    split_end = time.time()
    timings['split'] = split_end - split_start
    
    if show_progress:
        print(f"  ✓ SPLIT completato in {timings['split']:.3f}s\n")
    
    # ====================================================================
    # MERGE PHASE
    # ====================================================================
    merge_start = time.time()
    
    # Selezione partecipanti autorizzati
    if show_progress:
        print(f"  → Selezione {t_threshold} partecipanti autorizzati...", end=' ', flush=True)
    auth_subset = random.sample(range(n_partecipants), t_threshold)
    auth_mods = [participants[i]["mod"] for i in auth_subset]
    M_auth = prod(auth_mods)
    if show_progress:
        print("✓")
    
    # Ricostruzione homorfica CRT
    if show_progress:
        print(f"  → Ricostruzione homorfica CRT su {num_blocks} blocchi")
        pbar = ProgressBar(num_blocks, desc="    CRT Hom", width=50)
        
        encrypted_reconstructed_blocks = []
        
        for block_idx in range(num_blocks):
            encrypted_shares = [
                participants[i]["residues_enc_new"][block_idx] 
                for i in auth_subset
            ]
            
            encrypted_S_refreshed = homomorphic_crt(
                encrypted_shares, auth_mods, M_auth, public_key
            )
            
            enc_K = public_key.encrypt(K_values[block_idx] % M_auth)
            encrypted_S_final = encrypted_S_refreshed - enc_K
            
            encrypted_reconstructed_blocks.append(encrypted_S_final)
            pbar.update(1)
    else:
        encrypted_reconstructed_blocks = []
        
        for block_idx in range(num_blocks):
            encrypted_shares = [
                participants[i]["residues_enc_new"][block_idx] 
                for i in auth_subset
            ]
            
            encrypted_S_refreshed = homomorphic_crt(
                encrypted_shares, auth_mods, M_auth, public_key
            )
            
            enc_K = public_key.encrypt(K_values[block_idx] % M_auth)
            encrypted_S_final = encrypted_S_refreshed - enc_K
            
            encrypted_reconstructed_blocks.append(encrypted_S_final)
    
    # Decrittografia finale
    if show_progress:
        print(f"  → Decrittografia finale dei {num_blocks} blocchi")
        pbar = ProgressBar(num_blocks, desc="    Decrypt", width=50)
        
        reconstructed_blocks = []
        for i, enc_block in enumerate(encrypted_reconstructed_blocks):
            block_num = private_key.decrypt(enc_block) % M_auth
            reconstructed_blocks.append((block_num, blocks[i][1]))
            pbar.update(1)
    else:
        reconstructed_blocks = [
            (private_key.decrypt(enc_block) % M_auth, blocks[i][1])
            for i, enc_block in enumerate(encrypted_reconstructed_blocks)
        ]
    
    if show_progress:
        print("  → Ricostruzione testo finale...", end=' ', flush=True)
    final_text = blocks_to_text(reconstructed_blocks)
    if show_progress:
        print("✓")
    
    merge_end = time.time()
    timings['merge'] = merge_end - merge_start
    
    if show_progress:
        print(f"  ✓ MERGE completato in {timings['merge']:.3f}s\n")
    
    # Verifica correttezza
    is_correct = (input_text == final_text)
    
    return timings, is_correct


def main():
    """Funzione principale per testare diverse dimensioni di file"""
    
    # Dimensioni da testare
    test_sizes = {
        '100B': 100,
        '500B': 500,
        '1KB': 1024,
        '100KB': 100 * 1024,
        '1MB': 1024 * 1024,
    }
    
    results = {
        'sizes': [],
        'split_times': [],
        'merge_times': [],
        'total_times': [],
        'correctness': []
    }
    
    print("\n" + "="*60)
    print(" TESTING RRNS SECRET SHARING - BLOCK OPTIMIZED ")
    print("="*60)
    
    for size_name, size_bytes in test_sizes.items():
        print(f"\n{'='*60}")
        print(f"Testing {size_name} ({size_bytes} bytes)")
        print(f"{'='*60}\n")
        
        # Genera contenuto di test
        test_content = generate_test_file(size_bytes)
        
        # Esegui il test
        result = run_secret_sharing_test(test_content, show_progress=True)
        
        if result[0] is None:
            print("Test fallito per vincoli crittografici!")
            continue
        
        timings, is_correct = result
        
        # Salva i risultati
        results['sizes'].append(size_name)
        results['split_times'].append(timings['split'])
        results['merge_times'].append(timings['merge'])
        results['total_times'].append(timings['split'] + timings['merge'])
        results['correctness'].append(is_correct)
        
        # Stampa risultato finale
        status = "✓ SUCCESSO" if is_correct else "✗ FALLITO"
        print(f"{'─'*60}")
        print(f"Risultato: {status}")
        print(f"Tempo Split:  {timings['split']:.4f}s")
        print(f"Tempo Merge:  {timings['merge']:.4f}s")
        print(f"Tempo Totale: {timings['split'] + timings['merge']:.4f}s")
        print(f"{'─'*60}")
    
    # ====================================================================
    # GENERAZIONE GRAFICO
    # ====================================================================
    if len(results['sizes']) > 0:
        print("\n\nGenerazione grafico...")
        
        plt.figure(figsize=(12, 7))
        
        x_pos = np.arange(len(results['sizes']))
        width = 0.35
        
        bars1 = plt.bar(x_pos - width/2, results['split_times'], width, 
                        label='Split Time', color='#2ecc71', alpha=0.85, edgecolor='black', linewidth=1.2)
        bars2 = plt.bar(x_pos + width/2, results['merge_times'], width, 
                        label='Merge Time', color='#f39c12', alpha=0.85, edgecolor='black', linewidth=1.2)
        
        plt.xlabel('File Size', fontweight='bold', fontsize=13)
        plt.ylabel('Time (seconds)', fontweight='bold', fontsize=13)
        plt.title('Split vs Merge Times - RRNS Secret Sharing (Block Optimized)', 
                  fontweight='bold', fontsize=15, pad=20)
        plt.xticks(x_pos, results['sizes'], fontsize=11)
        plt.yticks(fontsize=11)
        plt.legend(fontsize=12, loc='upper left')
        plt.grid(axis='y', alpha=0.3, linestyle='--')
        
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height:.3f}s',
                        ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('rrns_split_vs_merge_blocks.png', dpi=300, bbox_inches='tight')
        print(f"✓ Grafico salvato come 'rrns_split_vs_merge_blocks.png'")
        plt.show()
    
    # ====================================================================
    # RIEPILOGO FINALE
    # ====================================================================
    print("\n" + "="*60)
    print(" RIEPILOGO FINALE")
    print("="*60)
    print(f"\n{'Size':<10} {'Split (s)':<12} {'Merge (s)':<12} {'Total (s)':<12} {'Status':<10}")
    print("-" * 60)
    for i, size in enumerate(results['sizes']):
        status = "✓ OK" if results['correctness'][i] else "✗ FAIL"
        print(f"{size:<10} {results['split_times'][i]:<12.4f} "
              f"{results['merge_times'][i]:<12.4f} "
              f"{results['total_times'][i]:<12.4f} "
              f"{status:<10}")
    print("="*60)
    
    if len(results['split_times']) > 0:
        avg_split = np.mean(results['split_times'])
        avg_merge = np.mean(results['merge_times'])
        print(f"\nTempo medio Split: {avg_split:.4f}s")
        print(f"Tempo medio Merge: {avg_merge:.4f}s")
        print(f"Rapporto Split/Merge: {avg_split/avg_merge:.2f}x")
        print(f"\n⚡ OTTIMIZZAZIONI:")
        print(f"   • Cifratura a BLOCCHI (riduzione ~{optimal_block_size}x operazioni)")
        print(f"   • Chiavi Paillier 256-bit (velocità massima)")
        print(f"   • Validazione vincolo: n_Paillier > max(share_RRNS)")
    
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()