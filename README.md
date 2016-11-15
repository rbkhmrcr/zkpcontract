# Zero-Knowledge Proof Verification Contract

In maths and in life, we often want to convince others that what we are saying/claiming/assuming has happened is true. However, occasionally we wish to prove such a statement is true without leaking any other information at all.

For example, if I wish to prove that 6 is not prime, I would show you 2x3 = 6 and so you could verify that this is true and 6 is not prime. However, this also leaks the factors of 6.
Imagine if the factors of the prime being secret was the foundation of an encryption algorithm. Leaking these to you in the proof would be detrimental to everyone.
So we need to find another way.

To prove in zero-knowledge that we have possession of the private key (x, with public key Y, in ECC, such that Y = xG), the zero knowledge proof (more specifically, sigma protocol) happens roughly in the following way:

- Witness commitment: W = g^w
- Random challenge: c (c = H(m), with m a message, in non-interactive zkps, otherwise c can be a random challenge generated on the fly by the verifier).
- Response: r = w - cx mod q, with q the order of the finite group.
- Verification: g^r.pub^c = W.

In EC world, we instead have:
- Witness commitment: W = wG, with G the generator of the EC group, w a scalar in Z_n, with n the order of G (in other words, we would have to add G to itself n times to get 1. EC groups are finite, cyclic groups!).
- Random challenge: c (again, c = H(m) if we wish the proof to be non-interactive).
- Response: r = w - cx mod n (with n the order of the group generator again).
- Verification: rG + cY = W.

To do this in ECC, we're going to have to use some ECC ourselves! So I'll make use of [ecsol](https://github.com/jbaylina/ecsol) (thanks jbaylina).

