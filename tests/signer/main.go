//go:build wasm

// Command signer makes keys and signs checkpoints for the tests, with the
// same Go packages that the verifier checks them with. It is compiled to
// WebAssembly and loaded by tests/e2e/testlog.ts; nothing of it is in the
// site.
//
// Cosignatures carry the time they were made, which these packages read from
// the clock. A test that wants a cosignature made at some other time sets the
// clock the module sees (see testlog.ts).
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"syscall/js"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// The kinds of key: a log's Ed25519 key, a witness's Ed25519 cosignature
// key, and an ML-DSA-44 key, which either may hold.
const (
	kindEd25519      = "ed25519"
	kindEd25519Cosig = "ed25519-cosignature"
	kindMLDSA44      = "ml-dsa-44"
)

type keyIn struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type keyOut struct {
	Error string `json:"error,omitempty"`
	SKey  string `json:"skey"`
	VKey  string `json:"vkey"`
}

func generate(in keyIn) (keyOut, error) {
	switch in.Kind {
	case kindEd25519, kindEd25519Cosig:
		skey, vkey, err := note.GenerateKey(rand.Reader, in.Name)
		if err != nil {
			return keyOut{}, err
		}
		if in.Kind == kindEd25519Cosig {
			if vkey, err = f_note.VKeyToCosignatureV1(vkey); err != nil {
				return keyOut{}, err
			}
		}
		return keyOut{SKey: skey, VKey: vkey}, nil
	case kindMLDSA44:
		skey, vkey, err := f_note.GenerateMLDSAKey(in.Name)
		return keyOut{SKey: skey, VKey: vkey}, err
	}
	return keyOut{}, errors.New("unknown kind of key")
}

type signIn struct {
	SKey string `json:"skey"`
	Kind string `json:"kind"`
	// Text is the checkpoint to sign: the text of a note.
	Text string `json:"text"`
}

type signOut struct {
	Error string `json:"error,omitempty"`
	// Line is the signature line, with its newline.
	Line string `json:"line"`
}

func sign(in signIn) (signOut, error) {
	var signer note.Signer
	var err error
	switch in.Kind {
	case kindEd25519:
		signer, err = note.NewSigner(in.SKey)
	case kindEd25519Cosig:
		signer, err = f_note.NewSignerForCosignatureV1(in.SKey)
	case kindMLDSA44:
		signer, err = f_note.NewMLDSASigner(in.SKey)
	default:
		err = errors.New("unknown kind of key")
	}
	if err != nil {
		return signOut{}, err
	}
	signed, err := note.Sign(&note.Note{Text: in.Text}, signer)
	if err != nil {
		return signOut{}, err
	}
	_, line, ok := strings.Cut(string(signed), "\n\n")
	if !ok {
		return signOut{}, errors.New("signing did not produce a signature line")
	}
	return signOut{Line: line}, nil
}

// export registers fn as a global function from one JSON string to another.
func export[In, Out any](name string, fn func(In) (Out, error)) {
	js.Global().Set(name, js.FuncOf(func(_ js.Value, args []js.Value) any {
		var in In
		err := json.Unmarshal([]byte(args[0].String()), &in)
		var out any
		if err == nil {
			out, err = fn(in)
		}
		if err != nil {
			out = map[string]string{"error": err.Error()}
		}
		b, _ := json.Marshal(out)
		return string(b)
	}))
}

func main() {
	export("signerKey", generate)
	export("signerSign", sign)
	js.Global().Set("signerReady", true)
	select {}
}
