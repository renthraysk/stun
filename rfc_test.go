package stun

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

// Some of the RFC tests use non zero padding bytes.
// @TODO we're modifying a global, that is very bad.
func setPaddingByte(b byte) {
	for i := range zeroPad {
		zeroPad[i] = b
	}
}

func TestRFC5769SampleRequest2_1(t *testing.T) {
	const software = "STUN test client"
	const username = "evtj:h6vY"
	const password = "VOkJxbRl1RmTxUk/WvJxBt"

	var txID = TxID{
		0xB7, 0xE7, 0xA7, 0x01,
		0xBC, 0x34, 0xD6, 0x86,
		0xFA, 0x87, 0xDF, 0xAE,
	}

	expected := []byte{
		0x00, 0x01, 0x00, 0x58, // Request type and message length
		0x21, 0x12, 0xa4, 0x42, // Magic cookie
		0xb7, 0xe7, 0xa7, 0x01, //  }
		0xbc, 0x34, 0xd6, 0x86, //  }  Transaction ID
		0xfa, 0x87, 0xdf, 0xae, //  }
		0x80, 0x22, 0x00, 0x10, //SOFTWARE attribute header
		0x53, 0x54, 0x55, 0x4e, //  }
		0x20, 0x74, 0x65, 0x73, //  }  User-agent...
		0x74, 0x20, 0x63, 0x6c, //  }  ...name
		0x69, 0x65, 0x6e, 0x74, //  }
		0x00, 0x24, 0x00, 0x04, //PRIORITY attribute header
		0x6e, 0x00, 0x01, 0xff, //ICE priority value
		0x80, 0x29, 0x00, 0x08, //ICE-CONTROLLED attribute header
		0x93, 0x2f, 0xf9, 0xb1, //  }  Pseudo-random tie breaker...
		0x51, 0x26, 0x3b, 0x36, //  }   ...for ICE control
		0x00, 0x06, 0x00, 0x09, //USERNAME attribute header
		0x65, 0x76, 0x74, 0x6a, //  }
		0x3a, 0x68, 0x36, 0x76, //  }  Username (9 bytes) and padding (3 bytes)
		0x59, 0x20, 0x20, 0x20, //  }
		0x00, 0x08, 0x00, 0x14, //MESSAGE-INTEGRITY attribute header
		0x9a, 0xea, 0xa7, 0x0c, //  }
		0xbf, 0xd8, 0xcb, 0x56, //  }
		0x78, 0x1e, 0xf2, 0xb5, //  }  HMAC-SHA1 fingerprint
		0xb2, 0xd3, 0xf2, 0x49, //  }
		0xc1, 0xb5, 0x71, 0xa2, //  }
		0x80, 0x28, 0x00, 0x04, //FINGERPRINT attribute header
		0xe5, 0x7a, 0x3b, 0xcf, //CRC32 fingerprint

	}
	setPaddingByte(' ') // RFC uses space for padding?!

	b := New(TypeBindingRequest, txID)
	b.SetSoftware(software)
	b.SetPriority(110, 1, 1)
	b.SetICEControlled(0x932FF9B151263B36)
	b.SetUsername(username)
	b.AddMessageIntegrity([]byte(password))
	b.AddFingerprint()

	raw, err := b.Build()
	if err != nil {
		t.Fatalf("failed to build: %v", err)
	}
	if !bytes.Equal(expected, raw) {
		t.Fatalf("failed build in occordance with RFC test vector")
	}

	var m Message

	if err := m.Unmarshal(raw, []byte(password)); err != nil {
		t.Fatalf("failed to unmarshal message: %v", err)
	}
}

func TestRFC5769Sample2_4(t *testing.T) {
	const username = "\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9"
	const realm = "example.org"
	const password = "TheMatrIX"
	const nonce = "f//499k954d6OL34oL9FSTvy64sA"
	txID := TxID{0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e}

	setPaddingByte(0)

	expected := []byte{
		0x00, 0x01, 0x00, 0x60, //    Request type and message length
		0x21, 0x12, 0xa4, 0x42, //    Magic cookie
		0x78, 0xad, 0x34, 0x33, // }
		0xc6, 0xad, 0x72, 0xc0, // }  Transaction ID
		0x29, 0xda, 0x41, 0x2e, // }
		0x00, 0x06, 0x00, 0x12, //    USERNAME attribute header
		0xe3, 0x83, 0x9e, 0xe3, // }
		0x83, 0x88, 0xe3, 0x83, // }
		0xaa, 0xe3, 0x83, 0x83, // }  Username value (0x18, bytes) and padding (2 bytes)
		0xe3, 0x82, 0xaf, 0xe3, // }
		0x82, 0xb9, 0x00, 0x00, // }
		0x00, 0x15, 0x00, 0x1c, //    NONCE attribute header
		0x66, 0x2f, 0x2f, 0x34, // }
		0x39, 0x39, 0x6b, 0x39, // }
		0x35, 0x34, 0x64, 0x36, // }
		0x4f, 0x4c, 0x33, 0x34, // }  Nonce value
		0x6f, 0x4c, 0x39, 0x46, // }
		0x53, 0x54, 0x76, 0x79, // }
		0x36, 0x34, 0x73, 0x41, // }
		0x00, 0x14, 0x00, 0x0b, //    REALM attribute header
		0x65, 0x78, 0x61, 0x6d, // }
		0x70, 0x6c, 0x65, 0x2e, // }  Realm value (0x11, bytes) and padding (1 byte)
		0x6f, 0x72, 0x67, 0x00, // }
		0x00, 0x08, 0x00, 0x14, //    MESSAGE-INTEGRITY attribute header
		0xf6, 0x70, 0x24, 0x65, // }
		0x6d, 0xd6, 0x4a, 0x3e, // }
		0x02, 0xb8, 0xe0, 0x71, // }  HMAC-SHA1 fingerprint
		0x2e, 0x85, 0xc9, 0xa2, // }
		0x8c, 0xa8, 0x96, 0x66, // }
	}

	b := New(TypeBindingRequest, txID)
	b.SetUsername(username)
	b.SetNonce([]byte(nonce))
	b.SetRealm(realm)
	b.AddLongTermMessageIntegrity(PasswordAlgorithmMD5, username, realm, password)
	raw, err := b.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if !bytes.Equal(expected, raw) {
		t.Fatal("build generated different output")
	}

	var m Message

	if err := m.Unmarshal(raw, []byte(password)); err != nil {
		t.Fatalf("failed to unmarshal message: %v", err)
	}
}

func TestRFC8489TestVectorB1(t *testing.T) {

	t.Skip("RFC Test Vector contains an error")

	const username = "\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9"
	const realm = "example.org"
	const password = "TheMatrIX"

	const nonce = "f//499k954d6OL34oL9FSTvy64sA"

	txID := TxID{0x78, 0xad, 0x34, 0x33,
		0xc6, 0xad, 0x72, 0xc0,
		0x29, 0xda, 0x41, 0x2e}

	expected := []byte{
		0x00, 0x01, 0x00, 0x9c, //Request type and message length
		0x21, 0x12, 0xa4, 0x42, //Magic cookie
		0x78, 0xad, 0x34, 0x33, //}
		0xc6, 0xad, 0x72, 0xc0, //}  Transaction ID
		0x29, 0xda, 0x41, 0x2e, //}
		0x00, 0x1e, 0x00, 0x20, //USERHASH attribute header
		0x4a, 0x3c, 0xf3, 0x8f, //}
		0xef, 0x69, 0x92, 0xbd, //}
		0xa9, 0x52, 0xc6, 0x78, //}
		0x04, 0x17, 0xda, 0x0f, //}  Userhash value (0x32, bytes)
		0x24, 0x81, 0x94, 0x15, //}
		0x56, 0x9e, 0x60, 0xb2, //}
		0x05, 0xc4, 0x6e, 0x41, //}
		0x40, 0x7f, 0x17, 0x04, //}
		0x00, 0x15, 0x00, 0x29, //NONCE attribute header
		0x6f, 0x62, 0x4d, 0x61, //}
		0x74, 0x4a, 0x6f, 0x73, //}
		0x32, 0x41, 0x41, 0x41, //}
		0x43, 0x66, 0x2f, 0x2f, //}
		0x34, 0x39, 0x39, 0x6b, //}  Nonce value and padding (3 bytes)
		0x39, 0x35, 0x34, 0x64, //}
		0x36, 0x4f, 0x4c, 0x33, //}
		0x34, 0x6f, 0x4c, 0x39, //}
		0x46, 0x53, 0x54, 0x76, //}
		0x79, 0x36, 0x34, 0x73, //}
		0x41, 0x00, 0x00, 0x00, //}
		0x00, 0x14, 0x00, 0x0b, //REALM attribute header
		0x65, 0x78, 0x61, 0x6d, //}
		0x70, 0x6c, 0x65, 0x2e, //}  Realm value (0x11, bytes) and padding (1 byte)
		0x6f, 0x72, 0x67, 0x00, //}
		0x00, 0x1c, 0x00, 0x20, //MESSAGE-INTEGRITY-SHA256 attribute header
		0xe4, 0x68, 0x6c, 0x8f, //}
		0x0e, 0xde, 0xb5, 0x90, //}
		0x13, 0xe0, 0x70, 0x90, //}
		0x01, 0x0a, 0x93, 0xef, //}  HMAC-SHA256 value
		0xcc, 0xbc, 0xcc, 0x54, //}
		0x4c, 0x0a, 0x45, 0xd9, //}
		0xf8, 0x30, 0xaa, 0x6d, //}
		0x6f, 0x73, 0x5a, 0x01, //}
	}

	b := New(TypeBindingRequest, txID)
	b.SetUserHash(username, realm)
	b.SetNonceWithSecurityFeatures(FeatureUserAnonyminity, []byte(nonce))
	b.SetRealm(realm)
	b.AddMessageIntegritySHA256([]byte(password))

	raw, err := b.Build()
	if err != nil {
		t.Fatalf("failed to build: %v", err)
	}
	if !bytes.Equal(raw, expected) {
		w := hex.Dumper(os.Stdout)
		w.Write(raw)
		w.Close()

		t.Fatalf("build generate different output")
	}
}
