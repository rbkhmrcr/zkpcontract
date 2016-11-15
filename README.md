# Zero-Knowledge Proof Verification Contract

In maths and in life, we often want to convince others that what we are saying/claiming/assuming has happened is true. However, occasionally we wish to prove such a statement is true without leaking any other information at all.

For example, if I wish to prove that 6 is not prime, I would show you 2x3 = 6 and so you could verify that this is true and 6 is not prime. However, this also leaks the factors of 6.
Imagine if the factors of the prime being secret was the foundation of an encryption algorithm. Leaking these to you in the proof would be detrimental to everyone.
So we need to find another way.

Zero knowledge proofs (more specifically, sigma protocols) happen roughly in the following way:

- Witness commitment: W = g^w
- Random challenge: c (c = H(m), with m a message, in non-interactive zkps, otherwise c can be a random challenge generated on the fly by the verifier).
- Response: r = w - cx mod q
- Verification: g^r pub^c = W
