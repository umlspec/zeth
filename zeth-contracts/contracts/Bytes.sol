// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

library Bytes {

    function sha256_digest_from_field_elements(uint input0, uint input1)
        internal pure returns (bytes32) {
        // The 32-byte digest is encoded as:
        // - input0: a field element containing the low order 253 bits
        // - input1: a field element containing the high order 3 bits
        //
        // Note that the bits are also packed in reverse order, so the
        // reassembled value must be bit-reversed.

        bytes32 recombined_reversed = bytes32(input0 + (input1 << 253));
        bytes32 recombined = flip_bit_endianness_bytes32(recombined_reversed);
        return recombined;
    }

    function bytes_to_bytes32(bytes memory b, uint offset)
        internal pure returns (bytes32) {
        bytes32 out;

        for (uint i = 0; i < 32; i++) {
            out |= bytes32(b[offset + i] & 0xFF) >> (i * 8);
        }
        return out;
    }

    function flip_bit_endianness_bytes32(bytes32 a)
        internal pure returns(bytes32) {
        uint r;
        uint b;
        for (uint i = 0; i < 32; i++) {
            b = (uint(a) >> ((31-i)*8)) & 0xff;
            b = reverse_byte(b);
            r += b << (i*8);
        }
        return bytes32(r);
    }

    function int256ToBytes8(uint256 input) internal pure returns (bytes8) {
        bytes memory inBytes = new bytes(32);
        assembly {
            mstore(add(inBytes, 32), input)
        }

        bytes memory subBytes = subBytes(inBytes, 24, 32);
        bytes8 resBytes8;
        assembly {
            resBytes8 := mload(add(subBytes, 32))
        }

        return resBytes8;
    }

    function subBytes(bytes memory inBytes, uint startIndex, uint endIndex)
        internal pure returns (bytes memory) {
        bytes memory result = new bytes(endIndex-startIndex);
        for(uint i = startIndex; i < endIndex; i++) {
            result[i-startIndex] = inBytes[i];
        }
        return result;
    }

    // Function used to get the decimal value of the public values on both side
    // of the joinsplit (given as primary input) from the hexadecimal primary
    // values
    function get_value_from_inputs(bytes8 valueBytes)
        internal pure returns(uint64) {
        bytes8 flippedBytes = flip_endianness_bytes8(valueBytes);
        uint64 value = get_int64_from_bytes8(flippedBytes);
        return value;
    }

    function flip_endianness_bytes8(bytes8 a) internal pure returns(bytes8) {
        uint64 r;
        uint64 b;
        for (uint i = 0; i < 8; i++) {
            b = (uint64(a) >> ((7-i)*8)) & 0xff;
            b = reverse_bytes8(b);
            r += b << (i*8);
        }
        return bytes8(r);
    }

    function reverse_bytes8(uint a) internal pure returns (uint8) {
        return uint8(reverse_byte(a));
    }

    function get_int64_from_bytes8(bytes8 input) internal pure returns(uint64) {
        return uint64(input);
    }

    function get_last_byte(bytes32 x) internal pure returns(bytes1) {
        return x[31];
    }

    // Reverses the bit endianness of the byte
    // Example:
    // Input: 8 (decimal) -> 0000 1000 (binary)
    // Output: 0001 0000 (binary) -> 16 (decimal)
    function reverse_byte(uint a) internal pure returns (uint) {
        uint c = 0xf070b030d0509010e060a020c0408000;

        return (( c >> ((a & 0xF)*8)) & 0xF0)   +
            (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }
}
