"""
Hill Cipher - Kelompok 9
Mata Kuliah: Kriptografi

Rantai: Kelompok 7 (Full Vigenere) -> Kelompok 9 (Hill Cipher) -> Kelompok 4 (Playfair)

Spesifikasi:
  - Hill Cipher 2x2, Key default: [[3,3],[2,5]]
  - Alphabet A=0..Z=25, Modulo 26
  - Block size: 2 huruf, Padding: X
"""

import sys

DEFAULT_KEY = [[3, 3], [2, 5]]


# ── MATEMATIKA ───────────────────────────────────────────────

def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def det_2x2(m):
    return m[0][0] * m[1][1] - m[0][1] * m[1][0]

def inverse_matrix_2x2(m):
    inv_det = mod_inverse(det_2x2(m) % 26)
    if inv_det is None:
        return None
    return [
        [(inv_det *  m[1][1]) % 26, (inv_det * -m[0][1]) % 26],
        [(inv_det * -m[1][0]) % 26, (inv_det *  m[0][0]) % 26],
    ]

def is_valid_key(m):
    return mod_inverse(det_2x2(m) % 26) is not None


# ── PREPROCESSING ────────────────────────────────────────────

def preprocess(text):
    cleaned = ''.join(c.upper() for c in text if c.isalpha())
    if len(cleaned) % 2 != 0:
        cleaned += 'X'
    return cleaned


# ── HILL CIPHER ──────────────────────────────────────────────

def hill_encrypt(plaintext, key):
    p = preprocess(plaintext)
    result = []
    for i in range(0, len(p), 2):
        p1, p2 = ord(p[i]) - 65, ord(p[i+1]) - 65
        result += [
            chr((key[0][0]*p1 + key[0][1]*p2) % 26 + 65),
            chr((key[1][0]*p1 + key[1][1]*p2) % 26 + 65),
        ]
    return ''.join(result).replace('J', 'I')

def hill_decrypt(ciphertext, key):
    inv = inverse_matrix_2x2(key)
    if inv is None:
        print("ERROR: Key tidak invertible.")
        return None
    return hill_encrypt(ciphertext, inv)


# ── FULL VIGENERE ────────────────────────────────────────────

def fv_decrypt(ciphertext, key):
    key = key.upper()
    ct  = ''.join(c.upper() for c in ciphertext if c.isalpha())
    return ''.join(
        chr((ord(c) - ord(key[i % len(key)]) + 26) % 26 + 65)
        for i, c in enumerate(ct)
    )


# ── TAMPILAN ─────────────────────────────────────────────────

def sep():
    print("-" * 50)

def show_matrix(m, label="Key Matrix"):
    print(f"{label}:")
    print(f"  [ {m[0][0]}  {m[0][1]} ]")
    print(f"  [ {m[1][0]}  {m[1][1]} ]")

def show_key_info(key):
    inv = inverse_matrix_2x2(key)
    show_matrix(key, "Key Matrix (enkripsi)")
    print()
    if inv:
        show_matrix(inv, "Inverse Matrix (dekripsi)")

def show_blocks(text, key, mode="enkripsi"):
    p = preprocess(text)
    mat = inverse_matrix_2x2(key) if mode == "dekripsi" else key
    print(f"Detail per blok ({mode}):")
    for i in range(0, len(p), 2):
        a, b = ord(p[i]) - 65, ord(p[i+1]) - 65
        c = (mat[0][0]*a + mat[0][1]*b) % 26
        d = (mat[1][0]*a + mat[1][1]*b) % 26
        print(f"  Blok {i//2+1}: {p[i]}{p[i+1]} -> {chr(c+65)}{chr(d+65)}")


# ── MENU 1: ENKRIPSI ─────────────────────────────────────────

def menu_encrypt(key):
    sep()
    print("ENKRIPSI HILL CIPHER")
    sep()
    show_key_info(key)
    print()

    pt = input("Plaintext : ").strip()
    if not pt:
        print("Input kosong."); return

    processed = preprocess(pt)
    ct = hill_encrypt(pt, key)

    print()
    print(f"Plaintext asli   : {pt}")
    print(f"Setelah preproses: {processed}")
    print(f"Ciphertext       : {ct}")
    print()
    show_blocks(pt, key, "enkripsi")
    sep()
    print(f"Kirim ke K4      : {ct}")


# ── MENU 2: DEKRIPSI (terima dari K7, enkripsi ulang ke K4) ──

def menu_decrypt(key):
    sep()
    print("DEKRIPSI FULL VIGENERE (dari K7) + ENKRIPSI HILL")
    sep()
    show_key_info(key)
    print()

    fv_ct  = input("Ciphertext dari K7 : ").strip()
    fv_key = input("Key Full Vigenere  : ").strip()
    if not fv_ct or not fv_key:
        print("Input kosong."); return

    pt       = fv_decrypt(fv_ct, fv_key)
    processed = preprocess(pt)
    ct_hill  = hill_encrypt(pt, key)

    print()
    print(f"Plaintext (hasil dekripsi FV) : {pt}")
    print(f"Setelah preproses             : {processed}")
    print()
    show_blocks(pt, key, "enkripsi")
    sep()
    print(f"Kirim ke K4      : {ct_hill}")


# ── MENU 3: UBAH KEY ─────────────────────────────────────────

def menu_change_key():
    sep()
    print("UBAH KEY MATRIX")
    sep()
    try:
        a = int(input("K[0][0]: "))
        b = int(input("K[0][1]: "))
        c = int(input("K[1][0]: "))
        d = int(input("K[1][1]: "))
        m = [[a, b], [c, d]]
        if not is_valid_key(m):
            print("PERINGATAN: Key tidak invertible mod 26!")
            if input("Tetap pakai? (y/n): ").lower() != 'y':
                return None
        else:
            print("Key valid.")
        return m
    except ValueError:
        print("Input harus angka integer.")
        return None


# ── MENU 4: LIHAT KEY ────────────────────────────────────────

def menu_show_key(key):
    sep()
    print("KEY MATRIX AKTIF")
    sep()
    inv = inverse_matrix_2x2(key)
    show_key_info(key)
    print()
    if inv:
        print(f"Determinan : {det_2x2(key) % 26} (mod 26)")
        print(f"Status     : VALID")
    else:
        print("Status     : TIDAK VALID (tidak invertible)")


# ── MAIN ─────────────────────────────────────────────────────

def main():
    key = [row[:] for row in DEFAULT_KEY]

    print()
    print("HILL CIPHER - Kelompok 9")
    sep()
    show_key_info(key)
    print()

    while True:
        print("\nMenu:")
        print("  1. Enkripsi")
        print("  2. Dekripsi")
        print("  3. Ubah Key Matrix")
        print("  4. Lihat Key Matrix")
        print("  0. Keluar")

        choice = input("\nPilih: ").strip()

        if   choice == '1': menu_encrypt(key)
        elif choice == '2': menu_decrypt(key)
        elif choice == '3':
            new_key = menu_change_key()
            if new_key:
                key = new_key
                print("Key berhasil diubah.")
        elif choice == '4': menu_show_key(key)
        elif choice == '0':
            print("Keluar."); sys.exit(0)
        else:
            print("Pilihan tidak valid.")

        input("\nEnter untuk lanjut...")


if __name__ == "__main__":
    main()