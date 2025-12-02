package main

import (
	"encoding/hex"
	"fmt"
	"log"
	u2sso "main/u2sso"
	"math"
	"time"
)

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lcrypto -lsecp256k1
// #include <stdlib.h>
// #include <stdint.h>
// #include <string.h>
// #include <openssl/rand.h>
// #include <secp256k1.h>
// #include <secp256k1_ringcip.h>
import "C"

var (
	ring_sizes = []int{8, 16, 32, 64, 128, 256, 512, 1024}
)

func main() {
	// gtimes := GenerateTime()
	// fmt.Println("Gen time")
	// for i := range ring_sizes {
	// 	fmt.Printf("%d\n", gtimes[i].Milliseconds())
	// }
	// fmt.Printf("\n")
	// stimes, vtimes := SignAndVerifyTimes()
	// fmt.Println("Sign time")
	// for i := range ring_sizes {
	// 	fmt.Printf("%d\n", stimes[i].Milliseconds())
	// }
	// fmt.Println()
	// fmt.Println("Ver time")
	// for i := range ring_sizes {
	// 	fmt.Printf("%d\n", vtimes[i].Milliseconds())
	// }
	sizes := SignatureSizes()
	for i := range ring_sizes {
		fmt.Printf("%d\n", sizes[i])
	}

	// // 3. auth workflow
	// // if commandFlag == "auth" {
	// if passkeypathFlag == "" {
	// 	fmt.Println("Please provide a passkeypath using the -keypath flag to store your passkey")
	// 	return
	// }
	// // service name
	// if snameFlag == "" {
	// 	fmt.Println("Please provide a service name using the -sname flag")
	// 	return
	// }
	// fmt.Println("service name size:", len(snameFlag))
	// serviceName, err = hex.DecodeString(snameFlag)
	// if err != nil {
	// 	fmt.Println("Please provide a valid service name of hex characters")
	// }

	// // challenge
	// if challengeFlag == "" {
	// 	fmt.Println("Please provide a challenge using the -challenge flag")
	// 	return
	// }
	// fmt.Println("challenge size:", len(challengeFlag))
	// challenge, err = hex.DecodeString(challengeFlag)
	// if err != nil {
	// 	fmt.Println("Please provide a valid challenge of hex characters")
	// }

	// // passkey
	// mskBytes, val = u2sso.LoadPasskey(passkeypathFlag)
	// if !val {
	// 	fmt.Println("could not create and load passkey")
	// 	return
	// }

	// proofAuthHex, val := u2sso.AuthProof(serviceName, challenge, mskBytes)
	// fmt.Println("proof auth hex format: ", proofAuthHex)
	// // }
}

func CreateNKeys(n int) ([][]byte, [][]byte) {
	passkeypathFlag := "./keys/msk%d"

	// 1. create passkeys and IDs
	MSKs := [][]byte{}
	IDList := [][]byte{}

	for i := range make([]int, n) {
		u2sso.CreatePasskey(fmt.Sprintf(passkeypathFlag, i))
		mskBytes1, _ := u2sso.LoadPasskey(fmt.Sprintf(passkeypathFlag, i))
		MSKs = append(MSKs, mskBytes1)

		idBytes1 := u2sso.CreateID(mskBytes1)
		IDList = append(IDList, idBytes1)
	}
	return MSKs, IDList
}

func GenerateTime() []time.Duration {
	times := make([]time.Duration, 0)

	for _, size := range ring_sizes {
		start := time.Now()
		CreateNKeys(size)
		elapsed := time.Since(start)

		times = append(times, elapsed)
	}
	return times
}

func SignAndVerifyTimes() ([]time.Duration, []time.Duration) {
	snameFlag := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	signTimes := make([]time.Duration, 0)
	verifyTimes := make([]time.Duration, 0)

	for _, size := range ring_sizes {
		MSKs, IDList := CreateNKeys(size)
		serviceName, err := hex.DecodeString(snameFlag)
		if err != nil {
			fmt.Println("Please provide a valid service name of hex characters")
			panic(err)
		}

		// challenge
		challenge := u2sso.CreateChallenge()
		// fmt.Println("challenge size:", len(challenge))

		// ring size
		idsize := len(IDList)
		// fmt.Println("total Id size:", idsize)
		currentm := math.Log2(float64(idsize))
		// ringSize := 1 // szhou: lol wait they use the term ring size in here, but what does it mean? does that mean subset of anonymity set
		// for i := 1; i < u2sso.M; i++ {
		// 	ringSize = u2sso.N * ringSize
		// 	if ringSize >= int(idsize.Int64()) {
		// 		currentm = i
		// 		break
		// 	}
		// }
		// fmt.Println("chosen ring size:", idsize.Int64(), " and m:", currentm)
		// fmt.Println("service name size:", len(snameFlag))
		index := 0

		start := time.Now()
		proofHex, spkBytes, _ := u2sso.RegistrationProof(int(index), int(currentm), int(idsize), serviceName, challenge, MSKs[0], IDList)
		elapsed := time.Since(start)

		// fmt.Println("proof hex format: ", proofHex)
		// fmt.Println("spkBytes hex format: ", hex.EncodeToString(spkBytes))
		// fmt.Println("N: ", idsize)

		signTimes = append(signTimes, elapsed)

		start = time.Now()
		verified := u2sso.RegistrationVerify(proofHex, int(currentm), idsize, serviceName, challenge, IDList, spkBytes)
		elapsed = time.Since(start)

		if !verified {
			fmt.Println("Registration FAILED!")
			panic(1)
		}
		fmt.Println("Registration SUCCEEDED!") // szhou: YAY lit
		verifyTimes = append(verifyTimes, elapsed)
	}
	return signTimes, verifyTimes
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

// func CreateSignatures() {

// }

func SignatureSizes() []uint64 {
	sizes := make([]uint64, 0)
	snameFlag := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	for _, size := range ring_sizes {
		MSKs, IDList := CreateNKeys(size)
		serviceName, err := hex.DecodeString(snameFlag)
		if err != nil {
			fmt.Println("Please provide a valid service name of hex characters")
			panic(err)
		}

		// challenge
		challenge := u2sso.CreateChallenge()

		idsize := len(IDList)
		currentm := math.Log2(float64(idsize)) // szhou: not sure what is happening here but
		index := 0

		proofHex, _, _ := u2sso.RegistrationProof(int(index), int(currentm), int(idsize), serviceName, challenge, MSKs[0], IDList)
		// diff := DeepSize(proofHex)

		sizes = append(sizes, uint64(len(proofHex)/2)) // szhou: since hex string is 2x the size of bytes
	}
	return sizes
}
