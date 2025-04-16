#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Proof-of-Concept for Memory Latency Gauntlet (MLG) PoW.

This script simulates a Proof-of-Work algorithm designed to be memory-latency
bound, potentially favoring hardware with lower memory latency over raw CPU
or memory bandwidth performance. It aims to be ASIC-resistant by requiring
a large memory scratchpad and performing dependent memory lookups.

Disclaimer: This is a Proof-of-Concept ONLY. It does not accurately simulate
hardware-level memory latency, cache effects, or provide cryptographic security
suitable for a real blockchain. Python's performance characteristics are vastly
different from native code (C/C++/Rust) and this script is purely used to test potentials.
"""

import hashlib
import os
import time
import struct
import xxhash

# --- Algorithm Parameters ---

# Size of the memory scratchpad in Megabytes.
# Larger values increase memory requirements and ASIC resistance, but slow down
# initialization and increase RAM usage. Recommended: 1024+ for real scenario.
# Use a smaller value (e.g., 128-512) for quicker PoC testing.
SCRATCHPAD_SIZE_MB = 256

# Size of data chunks read/processed in each iteration (bytes).
CHUNK_SIZE_BYTES = 64

# Number of dependent memory accesses (iterations) per hash attempt.
# Higher values increase the work per hash, emphasizing latency.
NUM_ITERATIONS = 10000

# --- Calculated Constants ---
SCRATCHPAD_SIZE_BYTES = SCRATCHPAD_SIZE_MB * 1024 * 1024
if SCRATCHPAD_SIZE_BYTES % CHUNK_SIZE_BYTES != 0:
    raise ValueError("SCRATCHPAD_SIZE_BYTES must be a multiple of CHUNK_SIZE_BYTES")
NUM_CHUNKS = SCRATCHPAD_SIZE_BYTES // CHUNK_SIZE_BYTES

# 64-bit mask (2**64 - 1) to keep state within uint64 range
MASK_64 = 0xFFFFFFFFFFFFFFFF

# --- Helper Functions ---

def initialize_scratchpad(seed_bytes, size_bytes):
    """
    Initializes and fills a memory scratchpad with pseudo-random data.

    Args:
        seed_bytes (bytes): Seed data (e.g., block header) to ensure deterministic
                            but unique scratchpad content for each challenge.
        size_bytes (int): The desired size of the scratchpad in bytes.

    Returns:
        bytearray: The initialized scratchpad.
    """
    print(f"Initializing {size_bytes / (1024*1024):.2f} MB scratchpad (this can take a moment)...")
    start_init_time = time.time()
    pad = bytearray(size_bytes)


    # Using the seed as the key makes the output unique per seed.
    # We hash the position index to ensure different data across the pad.
    hasher = hashlib.blake2b(digest_size=64, key=seed_bytes)
    num_hash_outputs_needed = (size_bytes + 63) // 64 # Ceiling division

    for i in range(num_hash_outputs_needed):
        # Include the index 'i' in the hash input to vary the output
        hasher_instance = hasher.copy() 
        hasher_instance.update(struct.pack('<Q', i)) 
        digest = hasher_instance.digest()

        offset = i * 64
        write_len = min(len(digest), size_bytes - offset)
        if write_len <= 0:
            break
        pad[offset : offset + write_len] = digest[:write_len]

    end_init_time = time.time()
    print(f"Scratchpad initialized in {end_init_time - start_init_time:.2f} seconds.")
    return pad

def perform_mlg_pow(header_bytes, nonce_bytes, scratchpad):
    """
    Performs the core Memory Latency Gauntlet PoW calculation.

    Args:
        header_bytes (bytes): The block header data (excluding nonce).
        nonce_bytes (bytes): The current nonce being tested.
        scratchpad (bytearray): The pre-initialized memory scratchpad.

    Returns:
        bytes: The final 32-byte PoW hash result.
    """
    # 1. Initial State & Address Calculation
    initial_input = header_bytes + nonce_bytes
    initial_hash = hashlib.sha256(initial_input).digest()

    # Derive initial memory address index and running state from the hash.
    addr_index = struct.unpack('<Q', initial_hash[:8])[0] % NUM_CHUNKS
    running_state = struct.unpack('<Q', initial_hash[8:16])[0]

    # 2. The Gauntlet Loop - Core of the PoW
    for i in range(NUM_ITERATIONS):
        # Calculate the byte offset for the current memory read
        current_addr_offset = addr_index * CHUNK_SIZE_BYTES

        # Simulate the memory read (this is the latency-sensitive step in theory)
        # Ensure slicing stays within bounds (should be guaranteed by % NUM_CHUNKS)
        data_chunk = scratchpad[current_addr_offset : current_addr_offset + CHUNK_SIZE_BYTES]

        # Perform light computation using the read data to update the state.
        chunk_val = struct.unpack('<Q', data_chunk[:8])[0]
        running_state ^= chunk_val
        running_state &= MASK_64

        # Rotate left by a few bits (e.g., 3)
        running_state = ((running_state << 3) | (running_state >> (64 - 3)))
        running_state &= MASK_64 # Keep state within 64 bits

        # Address Dependency: Calculate the *next* address based on the *current* data.
        # Use a fast non-cryptographic hash (xxhash) for speed.
        # Seed with loop counter 'i' for added pseudo-randomness variation per step.
        next_addr_hash_int = xxhash.xxh64(data_chunk, seed=i).intdigest()

        # Modulo operation maps the hash output to a valid chunk index.
        addr_index = next_addr_hash_int % NUM_CHUNKS

    # 3. Final Result Calculation
    # Pack the final 64-bit state back into bytes.
    final_state_bytes = struct.pack('<Q', running_state)
    # Hash the final state to produce the PoW result. SHA-256 is standard.
    final_hash = hashlib.sha256(final_state_bytes).digest()

    return final_hash

# --- Mining Simulation ---

def mine(header_bytes, difficulty_target, scratchpad):
    """
    Simulates the mining process by iterating through nonces.

    Args:
        header_bytes (bytes): The block header data.
        difficulty_target (bytes): The target threshold (hash must be lower than this).
        scratchpad (bytearray): The initialized scratchpad for this header.

    Returns:
        tuple(bytes, bytes, int) | None: (nonce, hash, attempts) if found, else None.
    """
    print("\n--- Starting Mining ---")
    print(f"Target Difficulty (numeric): < {int.from_bytes(difficulty_target, 'big')}")
    print(f"Target Difficulty (hex):    < {difficulty_target.hex()}")
    print(f"Using {NUM_ITERATIONS} iterations per hash attempt.")

    nonce_int = 0
    start_mine_time = time.time()
    last_update_time = start_mine_time
    hashes_since_update = 0

    while True:
        nonce_bytes = struct.pack('<Q', nonce_int)

        pow_result = perform_mlg_pow(header_bytes, nonce_bytes, scratchpad)
        hashes_since_update += 1

        # Check if the result meets the difficulty target
        if pow_result < difficulty_target:
            total_time = time.time() - start_mine_time
            print(f"\n--- Block Found! ---")
            print(f"Nonce (int): {nonce_int}")
            print(f"Nonce (hex): {nonce_bytes.hex()}")
            print(f"Found Hash:  {pow_result.hex()}")
            print(f"Total Attempts: {nonce_int + 1}")
            print(f"Time Taken:     {total_time:.2f} seconds")
            if total_time > 0:
                hps = (nonce_int + 1) / total_time
                print(f"Average Hashrate: {hps:.2f} H/s")
            return nonce_bytes, pow_result, nonce_int + 1

        # Update status periodically (e.g., every 2 seconds or N hashes)
        current_time = time.time()
        if current_time - last_update_time >= 2.0:
            duration = current_time - last_update_time
            hps = hashes_since_update / duration if duration > 0 else 0
            print(f"Status: Nonce {nonce_int}, Hashrate: {hps:.2f} H/s, Last Hash: {pow_result.hex()[:16]}...")
            last_update_time = current_time
            hashes_since_update = 0

        # Increment the nonce for the next attempt
        nonce_int += 1

        # Optional: Add a break condition for extremely long PoC runs
        # if nonce_int > 1000000: # Example limit
        #     print("Mining limit reached without finding a block.")
        #     return None

# --- Verification Function ---

def verify(header_bytes, nonce_bytes, expected_hash, difficulty_target, scratchpad):
    """
    Verifies a found PoW solution.

    Args:
        header_bytes (bytes): The block header data.
        nonce_bytes (bytes): The nonce that supposedly solves the PoW.
        expected_hash (bytes): The hash result produced by the miner.
        difficulty_target (bytes): The target threshold the hash must meet.
        scratchpad (bytearray): The *correctly initialized* scratchpad for the header.

    Returns:
        bool: True if the verification succeeds, False otherwise.
    """
    print("\n--- Verifying Solution ---")
    print(f"Header: {header_bytes[:20]}...")
    print(f"Nonce:  {nonce_bytes.hex()}")
    print(f"Reported Hash: {expected_hash.hex()}")
    print(f"Target:        {difficulty_target.hex()}")

    # Re-calculate the PoW hash using the provided header and nonce
    start_verify_time = time.time()
    calculated_hash = perform_mlg_pow(header_bytes, nonce_bytes, scratchpad)
    end_verify_time = time.time()

    print(f"Calculated Hash: {calculated_hash.hex()}")
    print(f"Verification Time: {end_verify_time - start_verify_time:.4f} seconds")

    # Check 1: Does the calculated hash match the expected hash?
    hash_match = (calculated_hash == expected_hash)
    print(f"Hash Match? {'OK' if hash_match else 'FAIL!'}")

    # Check 2: Does the hash meet the difficulty target?
    target_met = (calculated_hash < difficulty_target)
    print(f"Target Met? {'OK' if target_met else 'FAIL!'}")

    return hash_match and target_met

# --- Main Execution Block ---

if __name__ == "__main__":
    print("="*60)
    print(" Memory Latency Gauntlet (MLG) PoW - Proof of Concept")
    print("="*60)
    print(f"Config: Scratchpad={SCRATCHPAD_SIZE_MB}MB, Chunk={CHUNK_SIZE_BYTES}B, Iterations={NUM_ITERATIONS}")

    # 1. Define Dummy Block Data and Difficulty
    # Use slightly different header data for different runs if desired
    block_header = b"BlockData:Timestamp:MerkleRoot:PreviousHash:Etc:Example1"
    # Set a difficulty target. Lower value = harder.
    # Example: requires first two bytes (16 bits) to be zero.
    difficulty_target_hex = "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    # Example: requires first 18 bits to be zero (adjust first byte and nibble)
    # difficulty_target_hex = "0003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    difficulty_target = bytes.fromhex(difficulty_target_hex)

    # 2. Initialize Scratchpad (only needs to be done ONCE per block header)
    main_scratchpad = initialize_scratchpad(block_header, SCRATCHPAD_SIZE_BYTES)

    # 3. Start Mining Sim
    mining_result = mine(block_header, difficulty_target, main_scratchpad)

    # 4. Verification
    if mining_result:
        found_nonce, found_hash, attempts = mining_result
        # Re-use the same scratchpad for verification as it's based on the same header
        is_valid = verify(block_header, found_nonce, found_hash, difficulty_target, main_scratchpad)
        print(f"\nVerification Result: {'SUCCESS' if is_valid else 'FAILURE'}")
    else:
        print("\n Mining did not find a solution within limits (if any).")

    print("\nPoC Run Complete.")
