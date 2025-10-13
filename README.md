A work-in-progress MLS implementation with support for all ciphersuites. 

The code doesn't work and isn't tested, it's just here as a reference/draft to keep working on. 

We use OpenSSL for Ed448, while everything else uses RustCrypto and aws-lc. We generally prefer to implement most of the protocol in Rust when we can, while using aws-lc and OpenSSL for the rest.

Inspiration from:
- https://github.com/awslabs/mls-rs/ (used as a base for this code, most of the mls-rs code is still in this repository)
- https://github.com/openmls/openmls (referenced when converting some of the implementation from aws-lcc to rustcrypto)

There's currently a strange compilation error claiming that the pkey.rs file in the OpenSSL crate has a syntax error because its missing a semicolon. Adding the semicolon leads to another error claiming that the Curve type referenced in the crate isn't defined.

TODO:
- Make code work correctly
- Cleanup code
- Use RustCrypto for more of the cryptography
- Fix the test cases
- Performance benchmarking and optimization
- Security audit if this is going to be used for anything important