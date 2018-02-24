package skip32

import (
	"crypto/rand"
	"testing"
)

var test_key = []byte("s3cr3t k3y")
var test_data = map[uint32]uint32{
	42:        2444721374,
	4711:      3970196332,
	935425436: 42,
	798322584: 4711,
}

// keys shorter than 10 bytes will yield an error
func TestShortKey(t *testing.T) {
	var key = []byte("012345678")

	if _, err := Encrypt(key, 42); err == nil {
		t.Error("too short key not rejected")
	}

	if _, err := Decrypt(key, 42); err == nil {
		t.Error("too short key not rejected")
	}
}

// keys longer than 10 bytes will be truncated
func TestLongKey(t *testing.T) {
	var val_a, val_b uint32
	key_a := []byte("0123456789a")
	key_b := []byte("0123456789b")

	val_a, _ = Encrypt(key_a, 42)
	val_b, _ = Encrypt(key_b, 42)
	if val_a != val_b {
		t.Errorf("got %v and %v", val_a, val_b)
	}

	val_a, _ = Decrypt(key_a, 42)
	val_b, _ = Decrypt(key_b, 42)
	if val_a != val_b {
		t.Errorf("got %v and %v", val_a, val_b)
	}
}

// encryption yields the same result as skip32.c
func TestEncrypt(t *testing.T) {
	for decrypted, encrypted := range test_data {
		if result, _ := Encrypt(test_key, decrypted); result != encrypted {
			t.Errorf("got %v, expected %v", result, encrypted)
		}
	}
}

// decryption yields the same result as skip32.c
func TestDecrypt(t *testing.T) {
	for decrypted, encrypted := range test_data {
		if result, _ := Decrypt(test_key, encrypted); result != decrypted {
			t.Errorf("got %v, expected %v", result, decrypted)
		}
	}
}

// encryption and decryption are symmetrical
func TestSymmetry(t *testing.T) {
	var key = make([]byte, 10)
	rand.Read(key)

	for i := 0; i < 0xFF; i++ {
		start, _ := rand.Prime(rand.Reader, 32)

		start_val := uint32(start.Uint64())

		encrypted, _ := Encrypt(key, start_val)
		decrypted, _ := Decrypt(key, encrypted)
		if start_val != decrypted {
			t.Errorf("got %v, expected %v", decrypted, start_val)
		}
	}
}
