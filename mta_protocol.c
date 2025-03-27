/*
    High-Level Code Flow and Purpose
    This program implements a Secure Multiplicative-to-Additive (MtA) protocol using the secp256k1 elliptic curve parameters (commonly used in Bitcoin). The MtA protocol is a cryptographic technique that allows two parties to convert multiplicative shares (e.g., a * b) into additive shares (e.g., c + d) such that a * b ≡ c + d (mod n), where n is the curve order. This is a building block in secure multi-party computation (MPC), where parties compute a result together without revealing their private inputs.

    The program:

    Defines utility functions for XOR encryption, SHA-256 hashing, and printing large numbers.
    Implements the MtA protocol with a simulated Correlated Oblivious Transfer (OT) using XOR encryption and SHA-256.
    Runs test cases to verify the protocol works by ensuring c + d mod n equals a * b mod n.
*/

/*
    * Secure Multiplicative-to-Additive (MtA) Protocol with Simulated Correlated OT
    * Purpose: Converts multiplicative shares (a, b) into additive shares (c, d)
    *          such that a * b ≡ c + d (mod curve_order).
    * General Flow:
    * 1. Generate a random value u for Party 1 using SHA-256 hash of a and b.
    * 2. Compute ab = a * b mod curve_order.
    * 3. Compute v = ab - u mod curve_order for Party 2.
    * 4. Simulate Correlated OT: Encrypt u and v with XOR using a SHA-256-derived key.
    * 5. Decrypt the encrypted values to assign c = u and d = v.
    * 6. Clean up allocated memory.
    * Note: Uses secp256k1 curve order as modulus; assumes 256-bit inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/*
 * Constants for secp256k1 curve
 * FIELD_SIZE: 32 bytes (256 bits)
 * CURVE_ORDER: The order of secp256k1 curve in hex
 */
#define FIELD_SIZE 32
#define CURVE_ORDER "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

// XOR Encryption Function
void xor_encrypt(uint8_t *out, const uint8_t *a, const uint8_t *b, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// SHA256 Hashing Function 
void sha256_hash(uint8_t *out, const uint8_t *in, int len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, in, len);
    EVP_DigestFinal_ex(mdctx, out, NULL);
    
    EVP_MD_CTX_free(mdctx);
}

/*
 * Prints a BIGNUM in hexadecimal format
 */
void print_bn(const char *label, const BIGNUM *bn)
{
    char *hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

/*
  Secure Multiplicative-to-Additive (MtA) protocol with Correlated OT
  Converts multiplicative shares (a,b) to additive shares (c,d)
  such that a*b ≡ c + d mod n
  Uses XOR encryption and SHA-256 hashing
 */
void secure_mta_protocol(
    BIGNUM *a, BIGNUM *b, 
    BIGNUM *c, BIGNUM *d, 
    BIGNUM *curve_order, 
    BN_CTX *ctx
) {
    BIGNUM *u = BN_new();    // Random value chosen by Party 1
    BIGNUM *v = BN_new();    // Computed value for Party 2
    BIGNUM *tmp = BN_new();
    BIGNUM *ab = BN_new();   // a * b mod n

    // Step 1: Generate random u using SHA-256 for Party 1
    // coz we want value of a & b into hash_input, that's why using FIELD_SIZE * 2
    uint8_t hash_input[FIELD_SIZE * 2];
    uint8_t hash_output[FIELD_SIZE];

    // number of bytes need to represent a in binary
    int totalBytes = BN_num_bytes(a);   
    unsigned char *a_bin = malloc(totalBytes);

    totalBytes = BN_num_bytes(b);
    unsigned char *b_bin = malloc(totalBytes);

    // Converts a to binary, storing it in a_bin. Returns the length written
    int a_len = BN_bn2bin(a, a_bin);
    int b_len = BN_bn2bin(b, b_bin);
    
    memset(hash_input, 0, sizeof(hash_input));
    // Copies value of a_bin into hash_input (starting from hash_input)
    memcpy(hash_input, a_bin, a_len);
    // Copies value of b_bin into hash_input (starting from hash_input + a_len)
    memcpy(hash_input + a_len, b_bin, b_len);

    sha256_hash(hash_output, hash_input, a_len + b_len);
    BN_bin2bn(hash_output, FIELD_SIZE, u);  // Prepares u for arithmetic operations
    BN_mod(u, u, curve_order, ctx);         // u = u % curve

    // Step 2: Compute a * b mod n
    BN_mod_mul(ab, a, b, curve_order, ctx);

    // Step 3: Compute v = a * b - u mod n (this will be Party 2's share)
    BN_mod_sub(v, ab, u, curve_order, ctx);

    // Step 4: Simulate Correlated OT with XOR encryption
    // Party 1 encrypts u with a key derived from SHA-256
    uint8_t u_bin[FIELD_SIZE] = {0};
    uint8_t v_bin[FIELD_SIZE] = {0};
    uint8_t key[FIELD_SIZE];
    uint8_t u_encrypted[FIELD_SIZE];
    uint8_t v_encrypted[FIELD_SIZE];

    // Convert u and v to 32-byte binary
    BN_bn2binpad(u, u_bin, FIELD_SIZE);
    BN_bn2binpad(v, v_bin, FIELD_SIZE);

    // Generate encryption key from hash of a and b
    sha256_hash(key, hash_input, a_len + b_len);

    // Encrypt u and v with XOR
    xor_encrypt(u_encrypted, u_bin, key, FIELD_SIZE);
    xor_encrypt(v_encrypted, v_bin, key, FIELD_SIZE);

    // Step 5: Decrypt to get final shares (simulating OT exchange)
    // In a real OT, Party 1 sends u_encrypted, Party 2 sends v_encrypted,
    // and each decrypts with the shared key. Here, we decrypt immediately.
    uint8_t u_decrypted[FIELD_SIZE];
    uint8_t v_decrypted[FIELD_SIZE];
    xor_encrypt(u_decrypted, u_encrypted, key, FIELD_SIZE); // XOR with key again to decrypt
    xor_encrypt(v_decrypted, v_encrypted, key, FIELD_SIZE);

    // Convert back to BIGNUM
    BN_bin2bn(u_decrypted, FIELD_SIZE, c);
    BN_bin2bn(v_decrypted, FIELD_SIZE, d);

    // Cleanup
    BN_free(u);
    BN_free(v);
    BN_free(ab);
    free(a_bin);
    free(b_bin);
}

/*
 * Runs a test case with given 32-byte hex inputs
 */
void run_test_case(const char *name, const char *a_hex, const char *b_hex, BIGNUM *curve_order, BN_CTX *ctx)
{
    printf("\n=== Test Case: %s ===\n", name);

    // Convert giVen inputs int Hexadecimal Format and store into BIGNUM
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);

    print_bn("a (Party 1)        ", a);
    print_bn("b (Party 2)        ", b);

    // Get Multiplicative shares of given numbers
    BIGNUM *product = BN_new();
    BN_mod_mul(product, a, b, curve_order, ctx);
    print_bn("Expected (a*b mod n)", product);
    printf("\n");

    // Call secure_mta_protocol to get "c , d"
    BIGNUM *c = BN_new();
    BIGNUM *d = BN_new();
    secure_mta_protocol(a, b, c, d, curve_order, ctx);

    print_bn("c (Share 1)      ", c);
    print_bn("d (Share 2)      ", d);

    // Get Additive Shares of c and d, just to reconstruct original state
    BIGNUM *recon = BN_new();
    BN_mod_add(recon, c, d, curve_order, ctx);
    print_bn("Reconstructed (c+d mod n)", recon);

    // Verify current and original value
    if (BN_cmp(recon, product) == 0)
    {
        printf("RESULT: PASSED\n\n");
    }
    else
    {
        printf("RESULT: FAILED\n\n");
    }

    BN_free(a);
    BN_free(b);
    BN_free(product);
    BN_free(c);
    BN_free(d);
    BN_free(recon);
}

void run_all_test_cases(BIGNUM *curve_order, BN_CTX *ctx)
{
    run_test_case("1. Simple 2*3",
                  "0000000000000000000000000000000000000000000000000000000000000002",
                  "0000000000000000000000000000000000000000000000000000000000000003",
                  curve_order, ctx);

    run_test_case("2. Zero case 0*5",
                  "0000000000000000000000000000000000000000000000000000000000000000",
                  "0000000000000000000000000000000000000000000000000000000000000005",
                  curve_order, ctx);

    run_test_case("3. Curve order * 1",
                  CURVE_ORDER,
                  "0000000000000000000000000000000000000000000000000000000000000001",
                  curve_order, ctx);

    run_test_case("4. Curve order - 1 * 2",
                  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
                  "0000000000000000000000000000000000000000000000000000000000000002",
                  curve_order, ctx);

    run_test_case("5. Random 256-bit values",
                  "3A7EFB4C54231D9EF39E5D4F23C3D5B6A8D7E1F2C4A9B0D3E6F5A2B1C0D9E8F",
                  "5E4D3C2B1A09F8E7D6C5B4A39281706F5E4D3C2B1A09F8E7D6C5B4A3928170",
                  curve_order, ctx);

    run_test_case("6. Alternating Fs/0s * alternating 0s/Fs",
                  "FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000",
                  "00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF",
                  curve_order, ctx);

    run_test_case("7. All As * all 5s",
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                  "5555555555555555555555555555555555555555555555555555555555555555",
                  curve_order, ctx);

    run_test_case("8. Small primes 19*29",
                  "0000000000000000000000000000000000000000000000000000000000000013",
                  "000000000000000000000000000000000000000000000000000000000000001D",
                  curve_order, ctx);

    run_test_case("9. Max 256-bit * 1",
                  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                  "0000000000000000000000000000000000000000000000000000000000000001",
                  curve_order, ctx);

    run_test_case("10. Max 256-bit * Max 256-bit",
                  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                  curve_order, ctx);

    run_test_case("11. Random Numbers",
                  "47f2b3c87d1e64a09fbd5ea3c6902f5874ab31df8396c5e7d2fa08b47e19c3a2",
                  "a1cf4b5896e3d7f29bc047ad5f3281c6047fa2d35e8931b7fc42a08e69fbd137",
                  curve_order, ctx);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    // the curve_order (a constant modulus n for secp2561)
    BIGNUM *curve_order = BN_new();
    BN_hex2bn(&curve_order, CURVE_ORDER);

    run_all_test_cases(curve_order, ctx);

    BN_free(curve_order);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return 0;
}