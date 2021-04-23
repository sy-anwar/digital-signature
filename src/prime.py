from random import randrange, getrandbits

def is_prime(n: int,
             k: int = 128) :
    """
    Test if a number 'n' is prime or not using Miller-Rabin primality test

        n: the number to test
        k: the number of tests to perform on 'n'

    Return True if n is prime
    """
    if n == 3 :
        return True
    if n <= 1 or n%2 == 0 :
        return False

    # Find r and s
    r = n-1
    s = 0
    while r & 1 == 0 :
        r //= 2
        s += 1

    # Do k tests
    for _ in range(k) :
        a = randrange(2, n-1)
        x = pow(a, r, n)
        if x != 1 and x != n-1 :
            j = 1
            while j < s and x != n-1 :
                x = pow(x, 2, n)
                if x == 1 :
                    return False
                j += 1
            if x != n-1 :
                return False

    return True

def generate_n_bits_number(bits: int) :
    """
    Generate an n-bits odd integer randomly as a prime number candidate

        bits: the number of bits

    Returns an odd integer
    """
    if bits < 4 :
        raise Exception("The number of bits must be greater than 4")

    prime_candidate = getrandbits(bits)

    # Change MSB to 1 to ensure the number's bit length
    prime_candidate |= (1 << bits - 1)

    # Change LSB to 1 to ensure the number is odd
    prime_candidate |= 1

    return prime_candidate

def generate_prime_number(bits: int = 16) :
    """
    Generate a prime number

        bits: the number of bits
    """
    if bits < 4 :
        raise Exception("The number of bits must be greater than 4")

    prime_number = generate_n_bits_number(bits)
    while not is_prime(prime_number) :
        prime_number = generate_n_bits_number(bits)

    return prime_number

def is_coprime(p, q) :
        """
        Check if two given numbers are coprime or not
        """
        while q != 0 :
            p, q = q, p%q

        return p == 1
