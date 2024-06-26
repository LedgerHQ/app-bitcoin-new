# from https://github.com/bitcoin/bips/blob/b3701faef2bdb98a0d7ace4eedbeefa2da4c89ed/bip-0327/reference.py
# Distributed as part of BIP-0327 under the BSD-3-Clause license

# BIP327 reference implementation
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

# fmt: off

from typing import List, Optional, Tuple, NewType, NamedTuple
import hashlib
import secrets

#
# The following helper functions were copied from the BIP-340 reference implementation:
# https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py
#

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

def lift_x(b: bytes) -> Optional[Point]:
    x = int_from_bytes(b)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y & 1 == 0 else p-y)

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def has_even_y(P: Point) -> bool:
    assert not is_infinite(P)
    return y(P) % 2 == 0

def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x(pubkey)
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (P is None) or (r >= p) or (s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_even_y(R)) or (x(R) != r):
        return False
    return True

#
# End of helper functions copied from BIP-340 reference implementation.
#

PlainPk = NewType('PlainPk', bytes)
XonlyPk = NewType('XonlyPk', bytes)

# There are two types of exceptions that can be raised by this implementation:
#   - ValueError for indicating that an input doesn't conform to some function
#     precondition (e.g. an input array is the wrong length, a serialized
#     representation doesn't have the correct format).
#   - InvalidContributionError for indicating that a signer (or the
#     aggregator) is misbehaving in the protocol.
#
# Assertions are used to (1) satisfy the type-checking system, and (2) check for
# inconvenient events that can't happen except with negligible probability (e.g.
# output of a hash function is 0) and can't be manually triggered by any
# signer.

# This exception is raised if a party (signer or nonce aggregator) sends invalid
# values. Actual implementations should not crash when receiving invalid
# contributions. Instead, they should hold the offending party accountable.
class InvalidContributionError(Exception):
    def __init__(self, signer, contrib):
        self.signer = signer
        # contrib is one of "pubkey", "pubnonce", "aggnonce", or "psig".
        self.contrib = contrib

infinity = None

def xbytes(P: Point) -> bytes:
    return bytes_from_int(x(P))

def cbytes(P: Point) -> bytes:
    a = b'\x02' if has_even_y(P) else b'\x03'
    return a + xbytes(P)

def cbytes_ext(P: Optional[Point]) -> bytes:
    if is_infinite(P):
        return (0).to_bytes(33, byteorder='big')
    assert P is not None
    return cbytes(P)

def point_negate(P: Optional[Point]) -> Optional[Point]:
    if P is None:
        return P
    return (x(P), p - y(P))

def cpoint(x: bytes) -> Point:
    if len(x) != 33:
        raise ValueError('x is not a valid compressed point.')
    P = lift_x(x[1:33])
    if P is None:
        raise ValueError('x is not a valid compressed point.')
    if x[0] == 2:
        return P
    elif x[0] == 3:
        P = point_negate(P)
        assert P is not None
        return P
    else:
        raise ValueError('x is not a valid compressed point.')

def cpoint_ext(x: bytes) -> Optional[Point]:
    if x == (0).to_bytes(33, 'big'):
        return None
    else:
        return cpoint(x)

# Return the plain public key corresponding to a given secret key
def individual_pk(seckey: bytes) -> PlainPk:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return PlainPk(cbytes(P))

def key_sort(pubkeys: List[PlainPk]) -> List[PlainPk]:
    pubkeys.sort()
    return pubkeys

KeyAggContext = NamedTuple('KeyAggContext', [('Q', Point),
                                             ('gacc', int),
                                             ('tacc', int)])

def get_xonly_pk(keyagg_ctx: KeyAggContext) -> XonlyPk:
    Q, _, _ = keyagg_ctx
    return XonlyPk(xbytes(Q))

def key_agg(pubkeys: List[PlainPk]) -> KeyAggContext:
    pk2 = get_second_key(pubkeys)
    u = len(pubkeys)
    Q = infinity
    for i in range(u):
        try:
            P_i = cpoint(pubkeys[i])
        except ValueError:
            raise InvalidContributionError(i, "pubkey")
        a_i = key_agg_coeff_internal(pubkeys, pubkeys[i], pk2)
        Q = point_add(Q, point_mul(P_i, a_i))
    # Q is not the point at infinity except with negligible probability.
    assert(Q is not None)
    gacc = 1
    tacc = 0
    return KeyAggContext(Q, gacc, tacc)

def hash_keys(pubkeys: List[PlainPk]) -> bytes:
    return tagged_hash('KeyAgg list', b''.join(pubkeys))

def get_second_key(pubkeys: List[PlainPk]) -> PlainPk:
    u = len(pubkeys)
    for j in range(1, u):
        if pubkeys[j] != pubkeys[0]:
            return pubkeys[j]
    return PlainPk(b'\x00'*33)

def key_agg_coeff(pubkeys: List[PlainPk], pk_: PlainPk) -> int:
    pk2 = get_second_key(pubkeys)
    return key_agg_coeff_internal(pubkeys, pk_, pk2)

def key_agg_coeff_internal(pubkeys: List[PlainPk], pk_: PlainPk, pk2: PlainPk) -> int:
    L = hash_keys(pubkeys)
    if pk_ == pk2:
        return 1
    return int_from_bytes(tagged_hash('KeyAgg coefficient', L + pk_)) % n

def apply_tweak(keyagg_ctx: KeyAggContext, tweak: bytes, is_xonly: bool) -> KeyAggContext:
    if len(tweak) != 32:
        raise ValueError('The tweak must be a 32-byte array.')
    Q, gacc, tacc = keyagg_ctx
    if is_xonly and not has_even_y(Q):
        g = n - 1
    else:
        g = 1
    t = int_from_bytes(tweak)
    if t >= n:
        raise ValueError('The tweak must be less than n.')
    Q_ = point_add(point_mul(Q, g), point_mul(G, t))
    if Q_ is None:
        raise ValueError('The result of tweaking cannot be infinity.')
    gacc_ = g * gacc % n
    tacc_ = (t + g * tacc) % n
    return KeyAggContext(Q_, gacc_, tacc_)

def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def nonce_hash(rand: bytes, pk: PlainPk, aggpk: XonlyPk, i: int, msg_prefixed: bytes, extra_in: bytes) -> int:
    buf = b''
    buf += rand
    buf += len(pk).to_bytes(1, 'big')
    buf += pk
    buf += len(aggpk).to_bytes(1, 'big')
    buf += aggpk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, 'big')
    buf += extra_in
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('MuSig/nonce', buf))

def nonce_gen_internal(rand_: bytes, sk: Optional[bytes], pk: PlainPk, aggpk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None:
        rand = bytes_xor(sk, tagged_hash('MuSig/aux', rand_))
    else:
        rand = rand_
    if aggpk is None:
        aggpk = XonlyPk(b'')
    if msg is None:
        msg_prefixed = b'\x00'
    else:
        msg_prefixed = b'\x01'
        msg_prefixed += len(msg).to_bytes(8, 'big')
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b''
    k_1 = nonce_hash(rand, pk, aggpk, 0, msg_prefixed, extra_in) % n
    k_2 = nonce_hash(rand, pk, aggpk, 1, msg_prefixed, extra_in) % n
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2) + pk)
    return secnonce, pubnonce

def nonce_gen(sk: Optional[bytes], pk: PlainPk, aggpk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None and len(sk) != 32:
        raise ValueError('The optional byte array sk must have length 32.')
    if aggpk is not None and len(aggpk) != 32:
        raise ValueError('The optional byte array aggpk must have length 32.')
    rand_ = secrets.token_bytes(32)
    return nonce_gen_internal(rand_, sk, pk, aggpk, msg, extra_in)

def nonce_agg(pubnonces: List[bytes]) -> bytes:
    u = len(pubnonces)
    aggnonce = b''
    for j in (1, 2):
        R_j = infinity
        for i in range(u):
            try:
                R_ij = cpoint(pubnonces[i][(j-1)*33:j*33])
            except ValueError:
                raise InvalidContributionError(i, "pubnonce")
            R_j = point_add(R_j, R_ij)
        aggnonce += cbytes_ext(R_j)
    return aggnonce

SessionContext = NamedTuple('SessionContext', [('aggnonce', bytes),
                                               ('pubkeys', List[PlainPk]),
                                               ('tweaks', List[bytes]),
                                               ('is_xonly', List[bool]),
                                               ('msg', bytes)])

def key_agg_and_tweak(pubkeys: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool]):
    if len(tweaks) != len(is_xonly):
        raise ValueError('The `tweaks` and `is_xonly` arrays must have the same length.')
    keyagg_ctx = key_agg(pubkeys)
    v = len(tweaks)
    for i in range(v):
        keyagg_ctx = apply_tweak(keyagg_ctx, tweaks[i], is_xonly[i])
    return keyagg_ctx

def get_session_values(session_ctx: SessionContext) -> Tuple[Point, int, int, int, Point, int]:
    (aggnonce, pubkeys, tweaks, is_xonly, msg) = session_ctx
    Q, gacc, tacc = key_agg_and_tweak(pubkeys, tweaks, is_xonly)
    b = int_from_bytes(tagged_hash('MuSig/noncecoef', aggnonce + xbytes(Q) + msg)) % n
    try:
        R_1 = cpoint_ext(aggnonce[0:33])
        R_2 = cpoint_ext(aggnonce[33:66])
    except ValueError:
        # Nonce aggregator sent invalid nonces
        raise InvalidContributionError(None, "aggnonce")
    R_ = point_add(R_1, point_mul(R_2, b))
    R = R_ if not is_infinite(R_) else G
    assert R is not None
    e = int_from_bytes(tagged_hash('BIP0340/challenge', xbytes(R) + xbytes(Q) + msg)) % n
    return (Q, gacc, tacc, b, R, e)

def get_session_key_agg_coeff(session_ctx: SessionContext, P: Point) -> int:
    (_, pubkeys, _, _, _) = session_ctx
    pk = PlainPk(cbytes(P))
    if pk not in pubkeys:
        raise ValueError('The signer\'s pubkey must be included in the list of pubkeys.')
    return key_agg_coeff(pubkeys, pk)

def sign(secnonce: bytearray, sk: bytes, session_ctx: SessionContext) -> bytes:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    k_1_ = int_from_bytes(secnonce[0:32])
    k_2_ = int_from_bytes(secnonce[32:64])
    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:64] = bytearray(b'\x00'*64)
    if not 0 < k_1_ < n:
        raise ValueError('first secnonce value is out of range.')
    if not 0 < k_2_ < n:
        raise ValueError('second secnonce value is out of range.')
    k_1 = k_1_ if has_even_y(R) else n - k_1_
    k_2 = k_2_ if has_even_y(R) else n - k_2_
    d_ = int_from_bytes(sk)
    if not 0 < d_ < n:
        raise ValueError('secret key value is out of range.')
    P = point_mul(G, d_)
    assert P is not None
    pk = cbytes(P)
    if not pk == secnonce[64:97]:
        raise ValueError('Public key does not match nonce_gen argument')
    a = get_session_key_agg_coeff(session_ctx, P)
    g = 1 if has_even_y(Q) else n - 1
    d = g * gacc * d_ % n
    s = (k_1 + b * k_2 + e * a * d) % n
    psig = bytes_from_int(s)
    R_s1 = point_mul(G, k_1_)
    R_s2 = point_mul(G, k_2_)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # Optional correctness check. The result of signing should pass signature verification.
    assert partial_sig_verify_internal(psig, pubnonce, pk, session_ctx)
    return psig

def det_nonce_hash(sk_: bytes, aggothernonce: bytes, aggpk: bytes, msg: bytes, i: int) -> int:
    buf = b''
    buf += sk_
    buf += aggothernonce
    buf += aggpk
    buf += len(msg).to_bytes(8, 'big')
    buf += msg
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('MuSig/deterministic/nonce', buf))

def deterministic_sign(sk: bytes, aggothernonce: bytes, pubkeys: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, rand: Optional[bytes]) -> Tuple[bytes, bytes]:
    if rand is not None:
        sk_ = bytes_xor(sk, tagged_hash('MuSig/aux', rand))
    else:
        sk_ = sk
    aggpk = get_xonly_pk(key_agg_and_tweak(pubkeys, tweaks, is_xonly))

    k_1 = det_nonce_hash(sk_, aggothernonce, aggpk, msg, 0) % n
    k_2 = det_nonce_hash(sk_, aggothernonce, aggpk, msg, 1) % n
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0

    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2) + individual_pk(sk))
    try:
        aggnonce = nonce_agg([pubnonce, aggothernonce])
    except Exception:
        raise InvalidContributionError(None, "aggothernonce")
    session_ctx = SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
    psig = sign(secnonce, sk, session_ctx)
    return (pubnonce, psig)

def partial_sig_verify(psig: bytes, pubnonces: List[bytes], pubkeys: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, i: int) -> bool:
    if len(pubnonces) != len(pubkeys):
        raise ValueError('The `pubnonces` and `pubkeys` arrays must have the same length.')
    if len(tweaks) != len(is_xonly):
        raise ValueError('The `tweaks` and `is_xonly` arrays must have the same length.')
    aggnonce = nonce_agg(pubnonces)
    session_ctx = SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(psig, pubnonces[i], pubkeys[i], session_ctx)

def partial_sig_verify_internal(psig: bytes, pubnonce: bytes, pk: bytes, session_ctx: SessionContext) -> bool:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    s = int_from_bytes(psig)
    if s >= n:
        return False
    R_s1 = cpoint(pubnonce[0:33])
    R_s2 = cpoint(pubnonce[33:66])
    Re_s_ = point_add(R_s1, point_mul(R_s2, b))
    Re_s = Re_s_ if has_even_y(R) else point_negate(Re_s_)
    P = cpoint(pk)
    if P is None:
        return False
    a = get_session_key_agg_coeff(session_ctx, P)
    g = 1 if has_even_y(Q) else n - 1
    g_ = g * gacc % n
    return point_mul(G, s) == point_add(Re_s, point_mul(P, e * a * g_ % n))

def partial_sig_agg(psigs: List[bytes], session_ctx: SessionContext) -> bytes:
    (Q, _, tacc, _, R, e) = get_session_values(session_ctx)
    s = 0
    u = len(psigs)
    for i in range(u):
        s_i = int_from_bytes(psigs[i])
        if s_i >= n:
            raise InvalidContributionError(i, "psig")
        s = (s + s_i) % n
    g = 1 if has_even_y(Q) else n - 1
    s = (s + e * g * tacc) % n
    return xbytes(R) + bytes_from_int(s)
