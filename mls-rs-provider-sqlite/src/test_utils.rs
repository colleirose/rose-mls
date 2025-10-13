// Copyright by contributors to this project.
// SPDX-License-Identifier: MIT

use rand::RngCore;
pub fn gen_rand_bytes(size: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0; size];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}
