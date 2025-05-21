package common

import (
	"encoding/hex"
	"strings"

	"github.com/eager7/dogd/btcec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/vultisig/mobile-tss-lib/tss"
)

// TODO: remove once the plugin installation is implemented (resharding)
const (
	PluginPartyID   = "Rado’s MacBook Pro-FD0"
	VerifierPartyID = "Server-58253"
)

// TODO: pass if the key is ecdsa or eddsa
func DeriveAddress(compressedPubKeyHex, hexChainCode, derivePath string) (*common.Address, error) {
	derivedPubKeyHex, err := tss.GetDerivedPubKey(compressedPubKeyHex, hexChainCode, derivePath, false)
	if err != nil {
		return nil, err
	}

	derivedPubKeyBytes, err := hex.DecodeString(derivedPubKeyHex)
	if err != nil {
		return nil, err
	}

	derivedPubKey, err := btcec.ParsePubKey(derivedPubKeyBytes, btcec.S256())
	if err != nil {
		return nil, err
	}

	uncompressedPubKeyBytes := derivedPubKey.SerializeUncompressed()
	pubKeyBytesWithoutPrefix := uncompressedPubKeyBytes[1:]
	hash := crypto.Keccak256(pubKeyBytesWithoutPrefix)
	address := common.BytesToAddress(hash[12:])

	return &address, nil
}

func CheckIfPublicKeyIsValid(pubKeyBytes []byte, isEcdsa bool) bool {
	if isEcdsa {

		// Check for ECDSA (Compressed or Uncompressed)
		if len(pubKeyBytes) == 33 || len(pubKeyBytes) == 65 {
			firstByte := pubKeyBytes[0]

			// Compressed ECDSA key (starts with 0x02 or 0x03)
			if len(pubKeyBytes) == 33 && (firstByte == 0x02 || firstByte == 0x03) {
				return true // Valid Compressed ECDSA public key
			}

			// Uncompressed ECDSA key (starts with 0x04)
			if len(pubKeyBytes) == 65 && firstByte == 0x04 {
				return true // Valid Uncompressed ECDSA public key
			}
		}
	}

	if !isEcdsa {
		// Check for Ed25519 (EdDSA) - 32 bytes
		if len(pubKeyBytes) == 32 {
			return true // Valid EdDSA (Ed25519) public key
		}
	}

	return false
}

func GetSortingCondition(sort string) (string, string) {
	// Default sorting column
	orderBy := "created_at"
	orderDirection := "ASC"

	// Check if sort starts with "-"
	isDescending := strings.HasPrefix(sort, "-")
	columnName := strings.TrimPrefix(sort, "-") // Remove "-" if present

	// Ensure orderBy is a valid column name (prevent SQL injection)
	allowedColumns := map[string]bool{"updated_at": true, "created_at": true, "title": true}
	if allowedColumns[columnName] {
		orderBy = columnName // Use the provided column if valid
	}

	// Apply descending order if necessary
	if isDescending {
		orderDirection = "DESC"
	}

	return orderBy, orderDirection
}
