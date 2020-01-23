package main

import (
	"crypto/sha256"
	"egx/backend/lib"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/btcsuite/btcutil/base58"
)

func _checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

func Base58CheckEncode(input []byte, prefix [4]byte) string {
	b := []byte{}
	b = append(b, prefix[:]...)
	b = append(b, input[:]...)
	cksum := _checksum(b)
	b = append(b, cksum[:]...)
	return base58.Encode(b)
}

func Base58CheckDecode(input string) (_result []byte, _prefix []byte, _err error) {
	prefixLen := 4
	decoded := base58.Decode(input)
	if len(decoded) < 5 {
		return nil, nil, fmt.Errorf("CheckDecode: Invalid input format")
	}
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if _checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, nil, fmt.Errorf("CheckDecode: Checksum does not match")
	}
	prefix := decoded[:prefixLen]
	payload := decoded[prefixLen : len(decoded)-4]
	return payload, prefix, nil
}

func _tryBytePrefix(prefixBytes []byte, inputLength int32) string {
	input := lib.RandomBytes(inputLength)
	// Just need 4 bytes provisioned for the checksum; its value doesn't
	// actually matter.
	checksum := []byte{0x00, 0x00, 0x00, 0x00}
	b := []byte{}
	b = append(b, prefixBytes...)
	b = append(b, input[:]...)
	b = append(b, checksum[:]...)
	return base58.Encode(b)
}

func _tryPrefix(prefixVal uint64, prefixLength int32, inputLength int32) string {
	currentPrefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(currentPrefix, prefixVal)
	currentPrefix = currentPrefix[:prefixLength]

	return _tryBytePrefix(currentPrefix, inputLength)
}

func _match(ss string, prefix string) bool {
	return prefix == ss[:len(prefix)]
}

func _findRobustPrefix(stringPrefix string, minPrefixBytesLength int32, inputLength int32) []byte {
	if minPrefixBytesLength <= 0 {
		minPrefixBytesLength = 1
	}
	for prefixL := minPrefixBytesLength; prefixL <= 8; prefixL++ {
		maxValueBytes := make([]byte, 8)
		for ii := int32(0); ii < prefixL; ii++ {
			maxValueBytes[ii] = 0xFF
		}
		maxValue := binary.LittleEndian.Uint64(maxValueBytes)

		// Step 1: Find a byte prefix that maps to the prefix we want.
		for prefixValue := uint64(0); prefixValue < maxValue; prefixValue++ {
			if prefixValue%10000 == 0 {
				fmt.Printf(`Iteration number %d for string prefix "%s"`+"\n", prefixValue, stringPrefix)
			}

			badPrefixFound := false
			for ii := 0; ii < 10000; ii++ {
				if !_match(_tryPrefix(prefixValue, prefixL, inputLength), stringPrefix) {
					badPrefixFound = true
					//fmt.Println("bad prefix: ", _tryPrefix(prefixValue, inputLength))
					break
				}
			}
			if badPrefixFound {
				continue
			}

			// Found a good prefix int. Convert it back to bytes.
			ret := make([]byte, 8)
			binary.LittleEndian.PutUint64(ret, prefixValue)
			ret = ret[:prefixL]

			return ret
		}
	}

	return nil
}

func main() {
	stringPrefixesWeNeed := []string{"UN", "un", "tUN", "tun"}
	inputLengths := []int32{33, 32, 33, 32}
	bytePrefixesFound := [][]byte{}
	// Set to 0 or 1 to find the shortest byte prefix for each string prefix.
	minPrefixBytesLength := int32(3)

	for ii, _ := range stringPrefixesWeNeed {
		desiredStringPrefx := stringPrefixesWeNeed[ii]
		desiredInputLength := inputLengths[ii]
		bytePrefixesFound = append(bytePrefixesFound, _findRobustPrefix(desiredStringPrefx, minPrefixBytesLength, desiredInputLength))
	}

	for ii, _ := range stringPrefixesWeNeed {
		fmt.Printf(`Found byte prefix %#v for string prefix "%s"`+"\n", bytePrefixesFound[ii], stringPrefixesWeNeed[ii])
		for jj := 0; jj < 10; jj++ {
			fmt.Println(_tryBytePrefix(bytePrefixesFound[ii], inputLengths[ii]))
		}
	}

	os.Exit(0)
}
