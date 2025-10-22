
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

inv_s_box = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Tabela Rcon para a keyexpansion
Rcon = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]


# Funções Matemáticas do Corpo de Galois ---
def gadd(a, b):
    return a ^ b


def gmult(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = (a & 0x80)
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p & 0xFF


def print_state_matrix(title, state):
    """ Imprime uma matriz 4x4 de estado no formato hexadecimal """
    print(f"--- {title} ---")
    for r in range(4):
        # f"{b:02x}" formata o byte 'b' como 2 caracteres hexadecimais
        print(" ".join(f"{b:02x}" for b in state[r]))
    print()


class AES:
    def __init__(self, key):
        key_size = len(key)
        if key_size == 16:  # 128 bits
            self.Nk = 4
            self.Nr = 10
        elif key_size == 24:  # 192 bits
            self.Nk = 6
            self.Nr = 12
        elif key_size == 32:  # 256 bits
            self.Nk = 8
            self.Nr = 14
        else:
            raise ValueError("Tamanho da chave inválido.")

        self.Nb = 4
        self.w = self._key_expansion(key)

    @staticmethod
    def _sub_word(w):
        return [s_box[b] for b in w]

    @staticmethod
    def _rot_word(w):
        return w[1:] + w[:1]

    def _key_expansion(self, key):
        w = [0] * (self.Nb * (self.Nr + 1) * 4)
        for i in range(len(key)):
            w[i] = key[i]
        i = self.Nk * 4
        while i < (self.Nb * (self.Nr + 1) * 4):
            temp = w[i - 4: i]
            if (i // 4) % self.Nk == 0:
                temp = self._rot_word(temp)
                temp = self._sub_word(temp)
                rcon_word = Rcon[(i // 4) // self.Nk]
                for j in range(4):
                    temp[j] ^= rcon_word[j]
            elif self.Nk > 6 and (i // 4) % self.Nk == 4:
                temp = self._sub_word(temp)
            for j in range(4):
                w[i + j] = w[i - self.Nk * 4 + j] ^ temp[j]
            i += 4
        return w

    def _bytes_to_matrix(self, data):
        state = []
        for r in range(4):
            state.append([data[r + 4 * c] for c in range(self.Nb)])
        return state

    def _matrix_to_bytes(self, state):
        data = [0] * 16
        for r in range(4):
            for c in range(self.Nb):
                data[r + 4 * c] = state[r][c]
        return bytes(data)

    def _sub_bytes(self, state):
        for r in range(4):
            for c in range(self.Nb):
                state[r][c] = s_box[state[r][c]]

    @staticmethod
    def _shift_rows(state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]

    def _mix_columns(self, state):
        for c in range(self.Nb):
            col = [state[r][c] for r in range(4)]
            state[0][c] = gmult(0x02, col[0]) ^ gmult(0x03, col[1]) ^ col[2] ^ col[3]
            state[1][c] = col[0] ^ gmult(0x02, col[1]) ^ gmult(0x03, col[2]) ^ col[3]
            state[2][c] = col[0] ^ col[1] ^ gmult(0x02, col[2]) ^ gmult(0x03, col[3])
            state[3][c] = gmult(0x03, col[0]) ^ col[1] ^ col[2] ^ gmult(0x02, col[3])

    def _add_round_key(self, state, round_num):
        round_key_start = round_num * self.Nb * 4
        for c in range(self.Nb):
            for r in range(4):
                key_byte = self.w[round_key_start + c * 4 + r]
                state[r][c] ^= key_byte

    def _inv_sub_bytes(self, state):
        for r in range(4):
            for c in range(self.Nb):
                state[r][c] = inv_s_box[state[r][c]]

    @staticmethod
    def _inv_shift_rows(state):
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]

    def _inv_mix_columns(self, state):
        for c in range(self.Nb):
            col = [state[r][c] for r in range(4)]
            state[0][c] = gmult(0x0e, col[0]) ^ gmult(0x0b, col[1]) ^ gmult(0x0d, col[2]) ^ gmult(0x09, col[3])
            state[1][c] = gmult(0x09, col[0]) ^ gmult(0x0e, col[1]) ^ gmult(0x0b, col[2]) ^ gmult(0x0d, col[3])
            state[2][c] = gmult(0x0d, col[0]) ^ gmult(0x09, col[1]) ^ gmult(0x0e, col[2]) ^ gmult(0x0b, col[3])
            state[3][c] = gmult(0x0b, col[0]) ^ gmult(0x0d, col[1]) ^ gmult(0x09, col[2]) ^ gmult(0x0e, col[3])

    def _print_round_key(self, title, round_num):
        print(f"--- {title} (Rodada {round_num}) ---")
        key_start = round_num * self.Nb * 4
        key_matrix = []
        # Reconstrói a matriz da chave 4x4 a partir do array 'w'
        for r in range(4):
            row = []
            for c in range(self.Nb):
                row.append(self.w[key_start + c * 4 + r])
            key_matrix.append(row)

        # Reutiliza nossa função de impressão de matriz
        print_state_matrix("", key_matrix)  # Título já foi impresso

    # --- Função de Criptografia Normal (Rápida) ---
    def encrypt(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError("Texto puro deve ter 16 bytes.")
        state = self._bytes_to_matrix(plaintext)
        self._add_round_key(state, 0)
        for r in range(1, self.Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, r)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.Nr)
        return self._matrix_to_bytes(state)

    def encrypt_and_print_steps(self, plaintext):
        """
        Criptografa um bloco de 16 bytes, imprimindo
        cada estado intermediário, como na sua imagem.
        """
        if len(plaintext) != 16:
            raise ValueError("Texto puro deve ter 16 bytes.")

        state = self._bytes_to_matrix(plaintext)

        print("=" * 40)
        print("INÍCIO DA CRIPTOGRAFIA")
        print("=" * 40)
        # O estado antes da Rodada 0 é o próprio plaintext
        print_state_matrix("Início da Rodada 0 (Plaintext)", state)

        self._print_round_key("Chave de Rodada", 0)
        self._add_round_key(state, 0)
        # O estado após o AddRoundKey da Rodada 0 é o início da Rodada 1
        print_state_matrix("Após AddRoundKey (Início da Rodada 1)", state)

        for r in range(1, self.Nr):
            print("=" * 40)
            print(f"INÍCIO RODADA {r}")
            print("=" * 40)

            self._sub_bytes(state)
            print_state_matrix("Após SubBytes", state)

            self._shift_rows(state)
            print_state_matrix("Após ShiftRows", state)

            self._mix_columns(state)
            print_state_matrix("Após MixColumns", state)

            self._print_round_key("Chave de Rodada", r)
            self._add_round_key(state, r)
            print_state_matrix(f"Após AddRoundKey (Início Rodada {r + 1})", state)

        # Rodada final (sem MixColumns)
        print("=" * 40)
        print(f"INÍCIO RODADA FINAL ({self.Nr})")
        print("=" * 40)

        self._sub_bytes(state)
        print_state_matrix("Após SubBytes", state)

        self._shift_rows(state)
        print_state_matrix("Após ShiftRows", state)

        self._print_round_key("Chave de Rodada", self.Nr)
        self._add_round_key(state, self.Nr)

        print("=" * 40)
        print("FIM DA CRIPTOGRAFIA")
        print("=" * 40)
        print_state_matrix("Estado Final (Ciphertext)", state)

        return self._matrix_to_bytes(state)

    def decrypt(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError("Texto cifrado deve ter 16 bytes.")
        state = self._bytes_to_matrix(ciphertext)
        self._add_round_key(state, self.Nr)
        for r in range(self.Nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, r)
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, 0)
        return self._matrix_to_bytes(state)


def print_hex_flat(data, title=""):
    """ Função auxiliar para imprimir os bytes em hexadecimal (em linha) """
    print(title)
    hex_str = data.hex()
    # Formata em grupos de 4 bytes (8 caracteres hex), igual ao main.c
    row1 = " ".join(hex_str[i:i + 2] for i in range(0, 16, 2))
    row2 = " ".join(hex_str[i:i + 2] for i in range(16, 32, 2))
    print(row1)
    if row2:
        print(row2)
    print()


if __name__ == "__main__":
    # Chave de 16 bytes = 128 bits -> 10 Rodadas (Nr=10)
    key = bytes.fromhex('0f1571c947d9e8590cb7add6af7f6798')

    # Plaintext de 32 caracteres hex = 16 bytes (1 bloco)
    plaintext = bytes.fromhex('0123456789abcdeffedcba9876543210')

    # 1. Inicializa o AES e expande a chave
    aes_cipher = AES(key)

    # 2. Imprime o texto original (Bloco 1)
    print("Processando Bloco Único:")
    print_hex_flat(plaintext, "Mensagem original (Plaintext):")

    # 3. Criptografa (usando a nova função com impressão)
    ciphertext = aes_cipher.encrypt_and_print_steps(plaintext)

    print("\n--- RESULTADO FINAL ---")
    print_hex_flat(ciphertext, "Ciphertext:")

    # 4. Descriptografia
    decryptedtext = aes_cipher.decrypt(ciphertext)
    print_hex_flat(decryptedtext, "Mensagem Original: ")

    # Verificação
    assert plaintext == decryptedtext
    print("\nSucesso! Texto original e descriptografado são idênticos.")
