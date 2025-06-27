################################################################################
# Bitcoin Core Wrappers
################################################################################
import os
import struct
import random
import ctypes
import statistics
import subprocess
import sympy as sp
from rpc import *
from custom_types import *
from transaction import *
from time import time
from sage.all import *

def getParams():
    param = CParams()
    param.hashRounds = 1
    param.MillerRabinRounds = 32
    return param

class CBlock(ctypes.Structure):
    blocktemplate = {}
    _hash = "0"*32
    _fields_ = [ ("nVersion",    ctypes.c_uint32),
              ("hashPrevBlock",  ctypes.c_uint64 * 4 ),
              ("hashMerkleRoot", ctypes.c_uint64 * 4 ),
              ("nTime",          ctypes.c_uint32),
              ("nBits",          ctypes.c_uint16),
              ("nNonce",         ctypes.c_uint64),
              ("pOffset",        ctypes.c_uint16),
              ("dlog_answer",    ctypes.c_uint64 * 4 ),
              ("ECorder",        ctypes.c_uint64 * 4 ),
             ]

    def __init__(self):
        pass

    def get_next_block_to_work_on(self):
        blocktemplate      = rpc_getblocktemplate()
        self.blocktemplate = blocktemplate 

        prevBlock = blocktemplate["previousblockhash"]
        prevBlock = hashToArray(prevBlock)

        #If the block is empty then the merkleRootHash 
        #if the txid of the coinbase txn.
        merkleRoot = [0,0,0,0]

        self.dlog_answer         = (ctypes.c_uint64 * 4)(*([0]*4))
        self.ECorder             = (ctypes.c_uint64 * 4)(*([0]*4))
        self.hashPrevBlock       = (ctypes.c_uint64 * 4)(*prevBlock)
        self.hashMerkleRoot      = (ctypes.c_uint64 * 4)(*merkleRoot )
        self.nNonce   = 0
        self.nTime    = ctypes.c_uint32( blocktemplate["curtime"] )
        self.nVersion = ctypes.c_uint32( blocktemplate["version"] )
        self.nBits    = ctypes.c_uint16( int( blocktemplate["bits"], 16) )
        self.pOffset  = 0
        
        return self
    
    def serialize_block_header(self):
        #Get the data
        dlog_answer         = hex(uint256ToInt( self.dlog_answer)     )[2:].zfill(64)
        ECorder             = hex(uint256ToInt( self.ECorder)         )[2:].zfill(64)
        hashPrevBlock       = hex(uint256ToInt( self.hashPrevBlock)   )[2:].zfill(64)
        hashMerkleRoot      = hex(uint256ToInt( self.hashMerkleRoot)  )[2:].zfill(64)
        nNonce              = struct.pack("<Q", self.nNonce)
        pOffset             = struct.pack("<H", self.pOffset)
        nVersion            = struct.pack("<L", self.nVersion)
        nTime               = struct.pack("<L", self.nTime)
        nBits               = struct.pack("<H", self.nBits)
        
        #Reverse bytes of the hashes as little-Endian is needed for bitcoind
        dlog_answer         = bytes.fromhex(dlog_answer)[::-1]
        ECorder             = bytes.fromhex(ECorder)[::-1]
        hashPrevBlock       = bytes.fromhex(hashPrevBlock)[::-1] 
        hashMerkleRoot      = bytes.fromhex(hashMerkleRoot)[::-1]
                                                
        #Serialize in the right order
        CBlock1 = bytes()
        CBlock1 += nVersion
        CBlock1 += hashPrevBlock
        CBlock1 += hashMerkleRoot
        CBlock1 += nTime
        CBlock1 += nBits
        CBlock1 += nNonce
        CBlock1 += pOffset
        CBlock1 += dlog_answer
        CBlock1 += ECorder

        return CBlock1
    
    def __str__(self):
        
        #Get the data
        nVersion            = struct.pack("<L", self.nVersion).hex()
        hashPrevBlock       = hex(uint256ToInt( self.hashPrevBlock))[2:].zfill(64)
        hashMerkleRoot      = hex(uint256ToInt( self.hashMerkleRoot))[2:].zfill(64)
        nTime               = struct.pack("<L", self.nTime).hex()
        nBits               = struct.pack("<H", self.nBits).hex()
        nNonce              = struct.pack("<Q", self.nNonce).hex()
        pOffset             = struct.pack("<H", self.pOffset).hex()
        dlog_answer         = hex(uint256ToInt(self.dlog_answer))[2:].zfill(64)
        ECorder             = hex(uint256ToInt(self.ECorder))[2:].zfill(64)

        
        #Reverse bytes of the hashes as little-Endian is needed for bitcoind
        dlog_answer         = bytes.fromhex(dlog_answer)[::].hex()
        ECorder             = bytes.fromhex(ECorder)[::].hex()
        hashPrevBlock       = bytes.fromhex(hashPrevBlock)[::].hex() 
        hashMerkleRoot      = bytes.fromhex(hashMerkleRoot)[::].hex()
        
        s  = "CBlock class[HEX]: \n"
        s += "               nVersion: " + str(nVersion)            + "\n"
        s += "          hashPrevBlock: " + str(hashPrevBlock)       + "\n"
        s += "         hashMerkleRoot: " + str(hashMerkleRoot)      + "\n"
        s += "                  nTime: " + str(nTime)               + "\n"
        s += "                  nBits: " + str(nBits)               + "\n"
        s += "                 nNonce: " + str(nNonce)              + "\n"
        s += "                pOffset: " + str(pOffset)             + "\n"
        s += "            dlog_answer: " + str(dlog_answer)         + "\n"
        s += "                ECorder: " + str(ECorder)             + "\n\n"
        s += "CBlock class[DEC]: \n"
        s += "               nVersion: " + str(self.nVersion)       + "\n"
        s += "          hashPrevBlock: " + str(hashPrevBlock)       + "\n"
        s += "         hashMerkleRoot: " + str(hashMerkleRoot)      + "\n"
        s += "                  nTime: " + str(self.nTime)          + "\n"
        s += "                  nBits: " + str(self.nBits)          + "\n"
        s += "                 nNonce: " + str(self.nNonce)         + "\n"
        s += "                pOffset: " + str(self.pOffset)        + "\n"
        s += "            dlog_answer: " + str( uint256ToInt(self.dlog_answer) ) + "\n"
        s += "                ECorder: " + str( uint256ToInt(ECorder) )          + "\n\n"
    
        return s
    
    def int2lehex(self, value, width):
        """
        Convert an unsigned integer to a little endian ASCII hex string.
        Args:
            value (int): value
            width (int): byte width
        Returns:
            string: ASCII hex string
        """

        return value.to_bytes(width, byteorder='little').hex()

    def int2varinthex(self, value):
        """
        Convert an unsigned integer to little endian varint ASCII hex string.
        Args:
            value (int): value
        Returns:
            string: ASCII hex string
        """

        if value < 0xfd:
            return self.int2lehex(value, 1)
        elif value <= 0xffff:
            return "fd" + self.int2lehex(value, 2)
        elif value <= 0xffffffff:
            return "fe" + self.int2lehex(value, 4)
        else:
            return "ff" + self.int2lehex(value, 8)

    def prepare_block_for_submission(self):
        #Get block header
        submission = self.serialize_block_header().hex()
        
        # Number of transactions as a varint
        submission += self.int2varinthex(len(self.blocktemplate['transactions']))
        
         # Concatenated transactions data
        for tx in self.blocktemplate['transactions']:
            submission += tx['data']  
            
        return submission
    
    def rpc_submitblock(self):
        """Submit the mined block if it is still the current tip."""

        try:
            current_height = rpc_getblockcount()
        except Exception as exc:
            print(f"Failed to fetch current block height: {exc}")
            current_height = None

        template_height = self.blocktemplate.get("height")
        if (
            current_height is not None
            and template_height is not None
            and current_height > template_height
        ):
            print(
                "New block has already been found. Aborting stale block submission."
            )
            return None, None

        submission = self.prepare_block_for_submission()
        return rpc_submitblock(submission), submission
    
    def compute_raw_hash(self):
        """
        Compute the raw SHA256 double hash of a block header.
        Arguments:
            header (bytes): block header
        Returns:
            bytes: block hash
        """

        return hashlib.sha256(hashlib.sha256(self.serialize_block_header()).digest()).digest()[::-1]
    
    def r(self, n):
        if not (0 <= n < 1 << 256):
            raise ValueError("Input must be a 256-bit unsigned integer.")
        
        result = 0
        for i in range(32):
            result <<= 8
            result |= (n >> (8 * i)) & 0xFF
        return result
    
    def rr(self, n):
        if not (0 <= n < 1 << 1280):
            raise ValueError("Input must be a 1280-bit unsigned integer.")
        
        result = 0
        for i in range(160):
            result <<= 8
            result |= (n >> (8 * i)) & 0xFF
        return result
        
    def ggHash(self):
        #Block data
        block = self

        #Get parameters
        param = getParams()
       
        #Generate solution
        w = gHash( block, param) 
        w = uint1280ToInt(w)
        
        #Reverse byte order from gHash       
        w = self.rr(w)

        #Extract elliptive Curve data
        MASK =  1 << block.nBits 
        a  = w % MASK
        b  = ( w >> 256 ) % MASK
        p  = ( w >> 512 )  % MASK
        p |= (1 << (block.nBits-1) )
        x0 = ( w >> 768 ) % MASK
        g  = ( w >> 1024 ) % MASK

        pOffset = []

        for poffset in range(1<<16):
            if sp.isprime( p + poffset ):
                pOffset.append( poffset )

        return { "pOffset" : pOffset, "a" : a, "b" : b, "p" : p, "x0" : x0, "g" : g }

    def create_coinbase_txn(self, coinbase_message, scriptPubKey ):
        #Enforce the 100 character size limit
        if len(coinbase_message) > 100:
            raise ValueError(f"Coinbase message is { len(coinbase_message) } > limit. Limit is 100.")

        # Add an coinbase transaction to the block template transactions
        coinbase_tx = {}

        # Update the coinbase transaction with the new extra nonce
        coinbase_script = coinbase_message 
        coinbase_tx['data'] = tx_make_coinbase(coinbase_script, scriptPubKey, self.blocktemplate['coinbasevalue'], self.blocktemplate['height'] , self.blocktemplate['default_witness_commitment'])
        coinbase_tx['txid'] = tx_compute_hash(coinbase_tx['data'])

        block.blocktemplate['transactions'].insert(0, coinbase_tx)
    
        # Recompute the merkle root
        block.blocktemplate['merkleroot'] = tx_compute_merkle_root([tx['txid'] for tx in block.blocktemplate['transactions']])
        merkleRoot = uint256()
        merkleRoot = (ctypes.c_uint64 * 4)(*hashToArray( block.blocktemplate["merkleroot"])) 
        block.hashMerkleRoot = merkleRoot


    def mine(self, SCRIPT_PUB_KEY):
        blocktemplate = self.get_next_block_to_work_on()

        #Get parameters
        param = getParams()
        
        #Create coinbase txn
        self.create_coinbase_txn( "", SCRIPT_PUB_KEY )
    
        #Generate solution
        params = self.ggHash()

        
        #Set of parameters for elliptic curves
        for offset in params["pOffset"]:
                prime = params["p"] + offset

                E = EllipticCurve( GF( Integer( prime )  ), [ 0, 0, 0, Integer( params["a"] ), Integer( params["b"] ) ] )

            
                if is_prime( E.order()):
                    P1 = E.lift_x( Integer(params["x0"]), all = True)
                    G1 = E.lift_x( Integer(params["g"]), all = True)

                    if P1 and G1:
                        if is_prime(prime):
                            print("---------------------Prime: ", prime )

                        #Get the posive root
                        #defined to be r < p -r if r is the root.
                        P1 = P1[0] if P1[0].y() < P1[1].y() else P1[1]
                        G1 = G1[0] if G1[0].y() < G1[1].y() else G1[1]

                        start = time()
                        k = G1.log(P1)
                        end = time()
                    
                        print("        EC_order: ", E.order())
                        print("base field prime: ", params["p"] + offset )
                        print( "             EC: ", "y^2 = x^3 + " + str(params["a"]) + "x + " + str(params["b"]) )
                        print("         pOffset: ", offset )
                        print("            Base: ", P1 )
                        print("          Target: ", G1 )
                        print("      Exponent k: ", k )
                        print(" k*Base == Target", k*P1 == G1)
                        print("     mining time: ", end - start, " Seconds")
                        print()

                        EC_order = E.order()
                        self.pOffset = offset
                        self.dlog_answer = (ctypes.c_uint64 * 4)(*hashToArray( hex( self.r( int(k) ) ) ) )
                        self.ECorder = (ctypes.c_uint64 * 4)(*hashToArray( hex( self.r( int(EC_order)  ) ) ) )
                        self.rpc_submitblock()
                        print()


                        break             
    
if __name__ == '__main__':

    SCRIPT_PUB_KEY = ""
    if len(sys.argv) > 1:
        SCRIPT_PUB_KEY = sys.argv[1]
    else:
        print("No arguments provided. Provide ScriptPubKey.")
        print("  Usage:    python mining.py <SCRIPTPUBKEY> ")
        sys.exit()

    block = CBlock()
    block.mine( SCRIPT_PUB_KEY )
