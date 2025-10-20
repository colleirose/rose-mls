A work-in-progress MLS implementation with support for all ciphersuites, based on [mls-rs](https://github.com/awslabs/mls-rs).

The code doesn't work and isn't tested, it's just here as a reference/draft to keep working on.

We use OpenSSL for Ed448, while everything else uses RustCrypto and aws-lc. We generally prefer to implement most of the protocol in Rust when we can, while using aws-lc and OpenSSL for the rest. 

The point here is that we want to have simple code, limit dependencies and improve performance as much as possible while having secure and generally memory-safe code for all ciphersuites. We also want to support as many devices as possible while still maintaining security.

Current code is very messy, we will need to migrate the x509.rs from OpenSSL to aws-lc or RustCrypto but it's kept as it currently as a placeholder.

TODO (roughly in order):
- Basic code cleanup (styling, indentation, remove duplicate code, etc)
- Make the code work correctly
- Test to make sure that Ed448 keys work correctly
- Migrate most of the cryptography to RustCrypto
- Return more specific errors if a function fails
- Fix the test cases
- Performance benchmarking and optimization
- Security audit if this is going to be used for anything important