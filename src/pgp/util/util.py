from src.pgp.consts.consts import Algorithm, SIGNING_ALGORITHMS, ASYMMETRIC_ENCRYPTION_ALGORITHMS, \
    SYMMETRIC_ENCRYPTION_ALGORITHMS


def validate_if_algorithm_signing(algorithm: Algorithm):
    if algorithm not in SIGNING_ALGORITHMS:
        raise ValueError("algorithm must be RSA or DSA")


def validate_if_algorithm_asymmetric_encryption(algorithm: Algorithm):
    if algorithm not in ASYMMETRIC_ENCRYPTION_ALGORITHMS:
        raise ValueError("algorithm must be RSA")


def validate_if_algorithm_symmetric_encryption(algorithm: Algorithm):
    if algorithm not in SYMMETRIC_ENCRYPTION_ALGORITHMS:
        raise ValueError("algorithm must be CAST-128 or TripleDES")
