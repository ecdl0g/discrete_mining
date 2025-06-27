//Big Integer Arithmetic
#include <gmp.h>

//Blake2b, Scrypt and SHA3-512
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "cryptopp/whrlpool.h"
#include "cryptopp/scrypt.h"
#include "cryptopp/secblock.h"
#include "cryptopp/blake2.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"

//Fancy popcount implementation
#include "libpopcnt.h"

#include <cassert>
#include <iomanip>

typedef struct CBlock {
   uint32_t  nVersion;
   uint64_t  hashPrevBlock[4];
   uint64_t  hashMerkleRoot[4];
   uint32_t  nTime;
   uint16_t  nBits;
   uint64_t  nNonce;
   uint16_t  pOffset;
   uint64_t  dlog_answer[4];
} CBlock;

typedef struct CParams {
   uint32_t hashRounds;
   uint32_t MillerRabinRounds;
} CParams;

typedef struct uint1024 {
   uint64_t data[16];
} uint1024;

typedef struct uint1280 {
   uint64_t data[20];
} uint1280;

extern "C" uint1280 gHash( const CBlock block, const CParams params);
