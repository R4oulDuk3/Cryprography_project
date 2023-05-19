from src.pgp.consts.consts import Algorithm


def validate_if_algorithm_signing(algorithm: Algorithm):
    if algorithm not in [Algorithm.RSA, Algorithm.DSA]:
        raise ValueError("algorithm must be RSA or DSA")


def validate_if_algorithm_asymmetric_encryption(algorithm: Algorithm):
    if algorithm not in [Algorithm.RSA, Algorithm.ELGAMAL]:
        raise ValueError("algorithm must be RSA")

def validate_if_algorithm_symmetric_encryption(algorithm: Algorithm):
    if algorithm not in [Algorithm.CAST_128, Algorithm.TRIPLE_DES]:
        raise ValueError("algorithm must be CAST-128 or TripleDES")
