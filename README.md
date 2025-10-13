a work-in-progress MLS implementation with support for all ciphersuites, based on https://github.com/awslabs/mls-rs/

uses OpenSSL for Ed448 and uses aws-lc for everything other than Ed448

code doesn't work and isn't tested, just here as a reference/draft to keep working on in a few days

TODO:
- make code work correctly
- cleanup code
- fix the test cases
- maybe use rustcrypto for some of the cryptography? unsure
- performance benchmarking and optimization