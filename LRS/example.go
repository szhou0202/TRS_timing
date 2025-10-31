package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"time"

	"github.com/zbohm/lirisi/client"
	"github.com/zbohm/lirisi/ring"
)

func encodePublicKeyToDer(key *ecdsa.PublicKey) []byte {
	derKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		log.Fatal(err)
	}
	return derKey
}

// Auxiliary function for creating public keys.
func createPublicKeyList(curve elliptic.Curve, size int) []*ecdsa.PublicKey {
	publicKeys := make([]*ecdsa.PublicKey, size)
	for i := 0; i < size; i++ {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		publicKeys[i] = privateKey.Public().(*ecdsa.PublicKey)
	}
	return publicKeys
}

func createPrivateAndPublicKeyExample() {
	// Create private key
	status, privateKey := client.GeneratePrivateKey("prime256v1", "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", privateKey)
	// Create public key.
	status, publicKey := client.DerivePublicKey(privateKey, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", publicKey)
}

func baseExample(
	curveType func() elliptic.Curve,
	hashFnc func() hash.Hash,
	privateKey *ecdsa.PrivateKey,
	publicKeys []*ecdsa.PublicKey,
	message, caseIdentifier []byte,
) ([]byte, []byte) {
	// Make signature.
	status, signature := ring.Create(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}

	// Verify signature.
	status = ring.Verify(signature, publicKeys, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature verified OK")
	} else {
		fmt.Println("Signature verification Failure")
	}

	// Encode signature to format DER.
	status, signatureDer := client.EncodeSignarureToDER(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER:\n%s\n", hex.Dump(signatureDer))

	// Encode signature to format PEM.
	status, signaturePem := client.EncodeSignarureToPEM(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n%s\n", signaturePem)
	return signatureDer, signaturePem
}

func foldedKeysExample(privateKey *ecdsa.PrivateKey, foldedPublicKeys, signatureDer, signaturePem, message, caseIdentifier []byte) {
	// Verify signature in DER.
	status := client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER: Verified OK")
	} else {
		fmt.Println("Signature in DER: Verification Failure")
	}
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM: Verified OK")
	} else {
		fmt.Println("Signature in PEM: Verification Failure")
	}

	// Encode private key to DER.
	privateKeyDer, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	// Make first signature in format DER.
	status, signatureDer = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "DER")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER Nr.2:\n\n%s\n", hex.Dump(signatureDer))
	// Verify signature in DER.
	status = client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in DER Nr.2: Verification Failure")
	}

	// Make second signature in format PEM.
	status, signaturePem = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n\n%s\n", signaturePem)
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in PEM Nr.2: Verification Failure")
	}
	fmt.Println()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	gtimes := RunTenTimesAndAverage(GenerateTime)
	for i := range ring_sizes {
		fmt.Printf("%.1f\n", gtimes[i])
	}
	fmt.Printf("\n")
	stimes := RunTenTimesAndAverage(SignTime)
	for i := range ring_sizes {
		fmt.Printf("%.1f\n", stimes[i])
	}
	fmt.Printf("\n")
	vtimes := RunTenTimesAndAverage(VerifyTime)
	for i := range ring_sizes {
		fmt.Printf("%.1f\n", vtimes[i])
	}
}

var (
	ring_sizes = []int{8, 16, 32, 64, 128, 256, 512, 1024}
)

func CreateNKeys(n int) ([]*ecdsa.PublicKey, []*ecdsa.PrivateKey) {
	publicKeys := []*ecdsa.PublicKey{}
	privateKeys := []*ecdsa.PrivateKey{}

	for range make([]int, n) {
		// Create your private key.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		privateKeys = append(privateKeys, privateKey)

		// Add your public key to other public keys.
		publicKey := privateKey.Public().(*ecdsa.PublicKey)
		publicKeys = append(publicKeys, publicKey)
	}
	return publicKeys, privateKeys
}

func GenerateTime() []time.Duration {
	// szhou: what is the correct formulation of this?
	// should we generate all public keys and all private keys?
	// should we generate 1 private key and n public keys?
	// szhou: also i could make this statistical if i wanted lol
	// just run multiple times and take the average
	// szhou: also this does not encode the keys into PEM or DER
	times := make([]time.Duration, 0)

	for _, size := range ring_sizes {
		start := time.Now()
		CreateNKeys(size)
		elapsed := time.Since(start)

		times = append(times, elapsed)
	}
	return times
}

func SignTime() []time.Duration {
	times := make([]time.Duration, 0)

	for _, size := range ring_sizes {
		publicKeys, privateKeys := CreateNKeys(size)
		message := []byte("Hello world!")
		caseIdentifier := []byte("Round Nr.1")

		start := time.Now()
		_, _ = ring.Create(elliptic.P256, ring.HashCodes["sha3-256"], privateKeys[0], publicKeys, message, caseIdentifier)
		elapsed := time.Since(start)

		times = append(times, elapsed)
	}
	return times
}

func VerifyTime() []time.Duration {
	times := make([]time.Duration, 0)

	for _, size := range ring_sizes {
		publicKeys, privateKeys := CreateNKeys(size)
		message := []byte("Hello world!")
		caseIdentifier := []byte("Round Nr.1")

		_, signature := ring.Create(elliptic.P256, ring.HashCodes["sha3-256"], privateKeys[0], publicKeys, message, caseIdentifier)

		start := time.Now()
		_ = ring.Verify(signature, publicKeys, message, caseIdentifier)
		elapsed := time.Since(start)

		times = append(times, elapsed)
	}
	return times
}

func colAverages(lists [][]int) ([]float64, error) {
	if len(lists) == 0 {
		return nil, fmt.Errorf("no lists")
	}
	n := len(lists[0])
	for k := range lists {
		if len(lists[k]) != n {
			return nil, fmt.Errorf("mismatched lengths at list %d", k)
		}
	}

	avg := make([]float64, n)
	for i := 0; i < n; i++ {
		sum := 0
		for _, lst := range lists {
			sum += lst[i]
		}
		avg[i] = float64(sum) / float64(len(lists))
	}
	return avg, nil
}

func RunTenTimesAndAverage(funcToTime func() []time.Duration) []float64 {
	var allTimes [][]int
	for i := 0; i < 10; i++ {
		times := funcToTime()
		intTimes := make([]int, len(times))
		for j, t := range times {
			intTimes[j] = int(t.Nanoseconds())
		}
		allTimes = append(allTimes, intTimes)
	}
	avgTimes, err := colAverages(allTimes)
	if err != nil {
		log.Fatal(err)
	}
	return avgTimes
}
