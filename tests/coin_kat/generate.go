// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AlgoVoi.
// Independent differential-vector generator; not copied from go-algorand.
// Implements the documented spc seed and rejection-sampling wire rules using
// Go's standard-library SHAKE256. See README.md for the pinned reference.
package main

import (
    "bytes"
    "crypto/sha3"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "math/big"
    "os"
)

type vector struct {
    Name string `json:"name"`
    Participants string `json:"participants_commitment_hex"`
    Ln uint64 `json:"ln_proven_weight"`
    Signature string `json:"signature_commitment_hex"`
    Weight uint64 `json:"signed_weight"`
    Message string `json:"message_hash_hex"`
    Seed string `json:"seed_hex"`
    Coins []uint64 `json:"coins"`
    Draws int `json:"draws"`
}

func main() {
    weights := []uint64{1, 2, 1024, 1025, (1 << 63) + 1, ^uint64(0), 2029593440277877, 665003031377227}
    vectors := make([]vector, 0, len(weights))
    for i, weight := range weights {
        part, sig, msg := make([]byte, 64), make([]byte, 64), make([]byte, 32)
        for j := range part { part[j] = byte(j + i); sig[j] = byte(255 - j - i) }
        for j := range msg { msg[j] = byte(3*j + i) }
        ln := uint64(454197 + i)
        buf := new(bytes.Buffer)
        buf.Write([]byte{'s', 'p', 'c', 0})
        buf.Write(part)
        if err := binary.Write(buf, binary.LittleEndian, ln); err != nil { panic(err) }
        buf.Write(sig)
        if err := binary.Write(buf, binary.LittleEndian, weight); err != nil { panic(err) }
        buf.Write(msg)
        seed := buf.Bytes()
        bound := new(big.Int).Lsh(big.NewInt(1), 64)
        divisor := new(big.Int).SetUint64(weight)
        bound.Sub(bound, new(big.Int).Mod(new(big.Int).Set(bound), divisor))
        stream := sha3.NewSHAKE256()
        if _, err := stream.Write(seed); err != nil { panic(err) }
        coins := make([]uint64, 0, 32)
        draws := 0
        for len(coins) < cap(coins) {
            var raw [8]byte
            if _, err := io.ReadFull(stream, raw[:]); err != nil { panic(err) }
            draws++
            n := binary.LittleEndian.Uint64(raw[:])
            if new(big.Int).SetUint64(n).Cmp(bound) >= 0 { continue }
            coins = append(coins, n % weight)
        }
        vectors = append(vectors, vector{
            Name: fmt.Sprintf("weight-%d", weight), Participants: hex.EncodeToString(part),
            Ln: ln, Signature: hex.EncodeToString(sig), Weight: weight,
            Message: hex.EncodeToString(msg), Seed: hex.EncodeToString(seed), Coins: coins, Draws: draws,
        })
    }
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    if err := enc.Encode(vectors); err != nil { panic(err) }
}
