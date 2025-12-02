/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/rand"
	"fmt"
	stdmath "math"
	rand2 "math/rand"
	"privacy-perserving-audit/dory"
	"privacy-perserving-audit/threshold"
	"time"

	math "github.com/IBM/mathlib"
)

func main() {
	pp := make(map[int]int)
	signing := make(map[int]int)
	signing_std := make(map[int]float32)
	dualRingDory := make(map[int]int)
	appendProcess := make(map[int]int)
	verification := make(map[int]int)
	verify_std := make(map[int]float32)
	sizes := make(map[int]int)
	for n := 2; n <= 1024; n *= 2 {
		averagePP, averageSigning, averageVerification, averageDualRingDory, averageAppend, size, stdSign, stdVerify := benchmark(n)
		time.Sleep(time.Second)
		sizes[n] = size
		pp[n] = int(averagePP)
		signing[n] = int(averageSigning)
		verification[n] = int(averageVerification)
		dualRingDory[n] = int(averageDualRingDory)
		appendProcess[n] = int(averageAppend)
		signing_std[n] = stdSign
		verify_std[n] = stdVerify
		fmt.Printf(">>> %d, %d+%.3f, %d+%.3f\n", n, averageSigning, stdSign, averageVerification, stdVerify)
	}

	fmt.Println("Sizes:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, sizes[n])
	}
	fmt.Println()

	fmt.Println("Pre-processing:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, pp[n])
	}
	fmt.Println()

	fmt.Println("Signing:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d, %.3f)", n, signing[n], signing_std[n])
	}
	fmt.Println()

	fmt.Println("dualring+dory:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, dualRingDory[n])
	}
	fmt.Println()

	fmt.Println("Append tag:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, appendProcess[n])
	}
	fmt.Println()

	fmt.Println("Verify:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d, %.3f)", n, verification[n], verify_std[n])
	}
	fmt.Println()

}

func StdDev(xs []float32) float32 {
	if len(xs) == 0 {
		return 0
	}

	// mean
	var sum float32
	for _, x := range xs {
		sum += x
	}
	mean := sum / float32(len(xs))

	// variance
	var sq float32
	for _, x := range xs {
		d := x - mean
		sq += d * d
	}
	variance := sq / float32(len(xs)-1)

	return float32(stdmath.Sqrt(float64(variance)))
}

func benchmark(n int) (int64, int64, int64, int64, int64, int, float32, float32) {
	trials := 10

	privateKeys, ring := makeRing(n)
	doryPP := dory.GeneratePublicParams(n)

	var totalPPTime time.Duration

	for i := 0; i < trials; i++ {
		start := time.Now()
		threshold.ComputePreProcessedParams(dory.GeneratePublicParams(n), ring)
		totalPPTime += time.Since(start)
	}

	ppp := threshold.ComputePreProcessedParams(doryPP, ring)
	pp := threshold.PublicParams{
		DoryParams:         doryPP,
		PreProcessedParams: ppp,
	}

	msg := make([]byte, 32)
	_, err := rand.Read(msg)
	if err != nil {
		panic(err)
	}

	prefix := make([]byte, 32)
	_, err = rand.Read(prefix)
	if err != nil {
		panic(err)
	}

	time.Sleep(time.Millisecond * 500)

	signatures := make([]threshold.RingSignature, trials)
	var totalSigningTime time.Duration
	var totalVerificationTime time.Duration
	var totalDualRingDoryTime time.Duration
	var totalAppendTagTime time.Duration

	signTimes := make([]float32, trials)
	verifyTimes := make([]float32, trials)

	for i := 0; i < trials; i++ {
		sk := privateKeys[rand2.Intn(len(privateKeys))]
		startSigning := time.Now()
		σ := sk.Sign(pp, msg, prefix, ring)
		// Pre-process digest computation
		σ.DoryProof1.Digest()
		σ.DoryProof2.Digest()

		t := time.Since(startSigning)
		signTimes = append(signTimes, float32(t.Milliseconds()))
		totalSigningTime += t

		signatures[i] = σ
		time.Sleep(time.Millisecond * 200)

		startVerification := time.Now()
		err := σ.Verify(pp, msg, prefix)

		t = time.Since(startVerification)
		verifyTimes = append(verifyTimes, float32(t.Milliseconds()))
		totalVerificationTime += t

		if err != nil {
			panic(err)
		}

		startDualRingDory := time.Now()
		r, σ := sk.PreProcessRingProof(pp, ring)
		totalDualRingDoryTime += time.Since(startDualRingDory)
		time.Sleep(time.Millisecond * 200)

		startAppend := time.Now()
		sk.AppendTagProof(&σ, r, msg, prefix)
		totalAppendTagTime += time.Since(startAppend)

		time.Sleep(time.Millisecond * 200)

		// This is only for sanity check
		err = σ.Verify(pp, msg, prefix)
		if err != nil {
			panic(err)
		}
	}

	averageSign := totalSigningTime / time.Duration(trials)
	averageVerify := totalVerificationTime / time.Duration(trials)
	averageDualRingDory := totalDualRingDoryTime / time.Duration(trials)
	averageAppend := totalAppendTagTime / time.Duration(trials)
	averagePP := totalPPTime / time.Duration(trials)

	stdSign := StdDev(signTimes)
	stdVerify := StdDev(verifyTimes)

	var size int
	for _, σ := range signatures {
		size += len(σ.Bytes())
	}

	return averagePP.Milliseconds(), averageSign.Milliseconds(), averageVerify.Milliseconds(), averageDualRingDory.Milliseconds(), averageAppend.Microseconds(), size / len(signatures), stdSign, stdVerify
}

func makeRing(n int) ([]threshold.PrivateKey, threshold.Ring) {
	var privateKeys []threshold.PrivateKey
	var ring threshold.Ring
	for i := 0; i < n; i++ {
		pk, sk := threshold.KeyGen()
		privateKeys = append(privateKeys, sk)
		ring = append(ring, (*math.G1)(&pk))
	}

	return privateKeys, ring
}
