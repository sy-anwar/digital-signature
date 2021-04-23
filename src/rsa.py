import os
import prime

class RSA :
    currdir, _ = os.path.split(os.path.abspath(__file__))
    datadir = os.path.join(os.path.dirname(currdir), 'data')

    def __init__(self):
        self.p = 0
        self.q = 0
        self.n = 0
        self.phi_n = 0
        self.e = 0
        self.d = 0
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)

    def is_coprime(self, r, s) :
        """
        Check if two given numbers are coprime or not
        """
        while s != 0 :
            r, s = s, r%s

        return r == 1

    def extended_euclid_gcd(self, a, b) :
        """
        Returns 3 results, where:
        Referring to the equation ax + by = gcd(a, b)
            1st result is gcd(a, b)
            2nd result is x
            3rd result is y
        """
        r = b; old_r = a
        s = 0; old_s = 1
        t = 1; old_t = 0

        while r != 0 :
            quotient = old_r//r
            old_r, r = r, old_r-quotient*r
            old_s, s = s, old_s-quotient*s
            old_t, t = t, old_t-quotient*t
        return old_r, old_s, old_t

    def modulo_multiplicative_inverse(self, A, M) :
        """
        Returns multiplicative inverse of A under modulo of M, assuming that A and M are coprime
        """
        if not self.is_coprime(A, M) :
            raise Exception(f"{A} and {M} are not coprime")

        gcd, x, y = self.extended_euclid_gcd(A, M)

        while x < 0 :
            x += M

        return x

    def generate_key_pairs(self, bits: int = 16) :
        """
        Generate two key pairs: public key (e, n) and private key (d, n)
        """
        if bits < 4 :
            raise Exception("The number of bits must be greater than 4")
        self.p = prime.generate_prime_number(bits)
        self.q = prime.generate_prime_number(bits)
        self.n = self.p * self.q
        self.phi_n = (self.p-1) * (self.q-1)
        while not self.is_coprime(self.e, self.phi_n) :
            self.e = prime.generate_n_bits_number(bits)
        self.d = self.modulo_multiplicative_inverse(self.e, self.phi_n)
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)

    def save_public_key(self, filename: str) :
        """
        Save public key as *.pub file
        """
        public_key = self.get_public_key()
        with open(os.path.join(RSA.datadir, filename, (filename + '.pub')), 'w') as f_pub :
            f_pub.write(str(public_key[0]) + '\n')
            f_pub.write(str(public_key[1]))

    def save_private_key(self, filename: str) :
        """
        Save private key as *.pri file
        """
        private_key = self.get_private_key()
        with open(os.path.join(RSA.datadir, filename, (filename + '.pri')), 'w') as f_pri :
            f_pri.write(str(private_key[0]) + '\n')
            f_pri.write(str(private_key[1]))

    def save_key_pairs(self, filename: str) :
        """
        Save both key pairs: public and private key
        """
        if not os.path.exists(os.path.join(RSA.datadir, filename)) :
            os.makedirs(os.path.join(RSA.datadir, filename))
        self.save_public_key(filename)
        self.save_private_key(filename)

    def get_public_key(self) :
        """
        Returns the current public key
        """
        return self.public_key

    def get_private_key(self) :
        """
        Returns the current private key
        """
        return self.private_key

    def encrypt(self, plaintext: bytearray) -> str:
        """
        Encrypt plaintext by public key pair using RSA algorithm
        """
        if len(plaintext) == 0 :
            raise Exception("Plaintext cannot be empty")

        if not isinstance(plaintext, (bytes, bytearray)):
            raise Exception("Plaintext must be instance of bytes or bytearray")

        e, n = self.get_public_key()
        ciphertext = ''

        for i in range(len(plaintext)) :
            c = pow(plaintext[i], e, n)
            ciphertext += r'\{}'.format(hex(c)[1:])

        return ciphertext

    def decrypt(self, ciphertext: str) :
        """
        Decrypt ciphertext by private key pair using RSA algorithm
        """
        if len(ciphertext) == 0 :
            raise Exception("Ciphertext cannot be empty")

        d, n = self.get_private_key()
        ciphertext_list = ciphertext.split("\\x")
        plaintext = []

        for i in range(len(ciphertext_list)) :
            try :
                p = pow(int(ciphertext_list[i], 16), d, n)
                plaintext.append(p)
            except ValueError :
                continue

        return plaintext

# rsa = RSA()
# # rsa.generate_key_pairs(16)
# rsa.generate_key_pairs(64)
# # rsa.generate_key_pairs(256)
# # rsa.generate_key_pairs(1024)
# plaintext = "Kriptografi dan Koding"#.encode("utf-8")
# encrypted = rsa.encrypt(plaintext)
# print(encrypted)
# decrypted = rsa.decrypt(encrypted)
# print(decrypted)

# rsa.save_key_pairs('alice')