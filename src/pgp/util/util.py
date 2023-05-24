from src.pgp.consts.consts import Algorithm, SIGNING_ALGORITHMS, ASYMMETRIC_ENCRYPTION_ALGORITHMS, \
    SYMMETRIC_ENCRYPTION_ALGORITHMS, AlgorithmType


def validate_if_algorithm_signing(algorithm: Algorithm):
    if algorithm not in SIGNING_ALGORITHMS:
        raise ValueError("algorithm must be RSA or DSA")


def validate_if_algorithm_asymmetric_encryption(algorithm: Algorithm):
    if algorithm not in ASYMMETRIC_ENCRYPTION_ALGORITHMS:
        raise ValueError("algorithm must be RSA")


def validate_if_algorithm_symmetric_encryption(algorithm: Algorithm):
    if algorithm not in SYMMETRIC_ENCRYPTION_ALGORITHMS:
        raise ValueError("algorithm must be CAST-128 or TripleDES")


def validate_if_algorithm_matches_algorithm_type(algorithm: Algorithm, algorithm_type: AlgorithmType):
    if algorithm_type == AlgorithmType.SIGNING:
        validate_if_algorithm_signing(algorithm)
    elif algorithm_type == AlgorithmType.ASYMMETRIC_ENCRYPTION:
        validate_if_algorithm_asymmetric_encryption(algorithm)
    elif algorithm_type == AlgorithmType.SYMMETRIC_ENCRYPTION:
        validate_if_algorithm_symmetric_encryption(algorithm)
    else:
        raise ValueError("algorithm_type must be signing, asymmetric_encryption or symmetric_encryption")
