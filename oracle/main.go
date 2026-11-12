//go:build wasm

// Command oracle exposes the Go implementations of the transparency formats
// to JavaScript, as a WebAssembly module, so that the viewer's TypeScript
// verifier can be tested against them: github.com/transparency-dev/formats
// for policies, checkpoints, cosignatures and proofs, and
// golang.org/x/mod/sumdb/tlog for the Merkle tree.
//
// It is used only by tests. Every function takes one JSON string and returns
// one JSON string, which keeps the JavaScript boundary small enough to work
// unchanged under both the Go and TinyGo compilers.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"syscall/js"

	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/formats/policy"
	"github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type vkey struct {
	Name string `json:"name"`
	Key  string `json:"vkey"`
}

type group struct {
	Name      string   `json:"name"`
	Threshold uint     `json:"threshold"`
	Members   []string `json:"members"`
}

type policyOut struct {
	Error     string   `json:"error,omitempty"`
	Logs      []string `json:"logs"`
	Witnesses []vkey   `json:"witnesses"`
	Groups    []group  `json:"groups"`
	Quorum    string   `json:"quorum"`
}

func parsePolicy(text string) (*policy.TLogPolicy, policyOut) {
	p := &policy.TLogPolicy{}
	if err := p.Unmarshal([]byte(text)); err != nil {
		return nil, policyOut{Error: err.Error()}
	}
	out := policyOut{Logs: []string{}, Witnesses: []vkey{}, Groups: []group{}, Quorum: p.Quorum}
	for _, l := range p.Logs {
		out.Logs = append(out.Logs, l.VKey)
	}
	for _, w := range p.Witnesses {
		out.Witnesses = append(out.Witnesses, vkey{Name: w.Name, Key: w.VKey})
	}
	for _, g := range p.Groups {
		out.Groups = append(out.Groups, group{Name: g.Name, Threshold: g.Threshold, Members: g.Members})
	}
	return p, out
}

type checkpointIn struct {
	Policy     string `json:"policy"`
	Checkpoint string `json:"checkpoint"`
}

type checkpointOut struct {
	PolicyError string `json:"policyError,omitempty"`
	// Ok is the policy's verdict: signed by one of its logs and cosigned
	// according to its quorum.
	Ok     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Origin string `json:"origin,omitempty"`
	Size   uint64 `json:"size"`
	Hash   string `json:"hash,omitempty"`
	// LogSigned and Quorum are the two halves of the verdict, separately.
	LogSigned bool `json:"logSigned"`
	Quorum    bool `json:"quorum"`
	// Witnesses are the policy names of the witnesses with a valid
	// cosignature, sorted.
	Witnesses []string `json:"witnesses"`
}

func verifyCheckpoint(in checkpointIn) checkpointOut {
	p, parsed := parsePolicy(in.Policy)
	if p == nil {
		return checkpointOut{PolicyError: parsed.Error}
	}
	raw := []byte(in.Checkpoint)
	out := checkpointOut{Witnesses: []string{}}
	if cp, err := p.Verify(raw); err != nil {
		out.Error = err.Error()
	} else {
		out.Ok = true
		out.Origin = cp.Origin
		out.Size = cp.Size
		out.Hash = base64.StdEncoding.EncodeToString(cp.Hash)
	}
	out.Quorum = p.Satisfied(raw)
	for _, l := range p.Logs {
		if _, _, _, err := f_log.ParseCheckpoint(raw, l.Verifier.Name(), l.Verifier); err == nil {
			out.LogSigned = true
		}
	}
	for _, w := range p.Witnesses {
		if n, err := note.Open(raw, note.VerifierList(w.Verifier)); err == nil && len(n.Sigs) == 1 {
			out.Witnesses = append(out.Witnesses, w.Name)
		}
	}
	sort.Strings(out.Witnesses)
	return out
}

type proofJSON struct {
	Error      string   `json:"error,omitempty"`
	Index      uint64   `json:"index"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

func parseProof(text string) proofJSON {
	var pr proof.TLogProof
	if err := pr.Unmarshal([]byte(text)); err != nil {
		return proofJSON{Error: err.Error()}
	}
	out := proofJSON{Index: pr.Index, Hashes: []string{}, Checkpoint: string(pr.Checkpoint)}
	for _, h := range pr.Hashes {
		out.Hashes = append(out.Hashes, base64.StdEncoding.EncodeToString(h[:]))
	}
	return out
}

func formatProof(in proofJSON) string {
	pr := proof.TLogProof{Index: in.Index, Checkpoint: []byte(in.Checkpoint)}
	for _, h := range in.Hashes {
		b, err := base64.StdEncoding.DecodeString(h)
		if err != nil || len(b) != 32 {
			return ""
		}
		pr.Hashes = append(pr.Hashes, [32]byte(b))
	}
	return string(pr.Marshal())
}

// stored builds tlog's stored-hash sequence from leaf hashes.
type stored []tlog.Hash

func (s stored) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		out[i] = s[x]
	}
	return out, nil
}

type treeIn struct {
	// Leaves is the leaf hashes, hex-encoded and concatenated.
	Leaves string `json:"leaves"`
	Size   int64  `json:"size"`
	Index  int64  `json:"index"`
}

type treeOut struct {
	Error string   `json:"error,omitempty"`
	Root  string   `json:"root"`
	Proof []string `json:"proof"`
}

func tree(in treeIn) treeOut {
	b, err := hex.DecodeString(in.Leaves)
	if err != nil || int64(len(b)) < in.Size*32 {
		return treeOut{Error: "bad leaves"}
	}
	var s stored
	for i := int64(0); i < in.Size; i++ {
		var h tlog.Hash
		copy(h[:], b[i*32:])
		hs, err := tlog.StoredHashesForRecordHash(i, h, s)
		if err != nil {
			return treeOut{Error: err.Error()}
		}
		s = append(s, hs...)
	}
	root, err := tlog.TreeHash(in.Size, s)
	if err != nil {
		return treeOut{Error: err.Error()}
	}
	out := treeOut{Root: hex.EncodeToString(root[:]), Proof: []string{}}
	if in.Index >= 0 {
		p, err := tlog.ProveRecord(in.Size, in.Index, s)
		if err != nil {
			return treeOut{Error: err.Error()}
		}
		for _, h := range p {
			out.Proof = append(out.Proof, hex.EncodeToString(h[:]))
		}
	}
	return out
}

type signatureOut struct {
	Name  string `json:"name"`
	KeyID uint32 `json:"keyId"`
	// Role is "log", "witness", or "unknown" for a key outside the policy.
	Role string `json:"role"`
	// Witness is the policy's name for a witness.
	Witness string `json:"witness,omitempty"`
	// Alg is the key's signature type byte.
	Alg byte `json:"alg"`
	// Status is "valid", "invalid" or "unknown-key".
	Status string `json:"status"`
	// Timestamp is a valid cosignature's time, in decimal Unix seconds.
	Timestamp string `json:"timestamp,omitempty"`
}

type inspectOut struct {
	PolicyError string `json:"policyError,omitempty"`
	// Malformed is set if the input is not a signed checkpoint at all.
	Malformed string `json:"malformed,omitempty"`
	// Ok and Error are the policy's verdict, from policy.Verify.
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Text is the signed text of the note.
	Text       string   `json:"text"`
	Origin     string   `json:"origin"`
	Size       string   `json:"size"`
	Hash       string   `json:"hash"`
	Extensions []string `json:"extensions"`
	// Signatures are the note's signature lines, in order.
	Signatures []signatureOut `json:"signatures"`
	LogSigned  bool           `json:"logSigned"`
	Quorum     bool           `json:"quorum"`
}

// keyAlg returns the signature type byte of a vkey.
func keyAlg(vkey string) byte {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return 0
	}
	b, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(b) == 0 {
		return 0
	}
	return b[0]
}

// inspect reports everything the page shows about a checkpoint: the policy's
// verdict, and what became of each signature line. The verdict is
// policy.Verify's; the rest is assembled by opening the note once per key.
func inspect(in checkpointIn) inspectOut {
	p, parsed := parsePolicy(in.Policy)
	if p == nil {
		return inspectOut{PolicyError: parsed.Error}
	}
	raw := []byte(in.Checkpoint)
	out := inspectOut{Extensions: []string{}, Signatures: []signatureOut{}}

	// Opening a note with no known keys fails in a way that hands back the
	// parsed note, signature lines included.
	_, err := note.Open(raw, note.VerifierList())
	var unverified *note.UnverifiedNoteError
	if !errors.As(err, &unverified) {
		out.Malformed = "not a signed note"
		if err != nil {
			out.Malformed = err.Error()
		}
		return out
	}
	n := unverified.Note
	out.Text = n.Text
	var cp f_log.Checkpoint
	rest, err := cp.Unmarshal([]byte(n.Text))
	if err != nil {
		out.Malformed = err.Error()
		return out
	}
	out.Origin = cp.Origin
	out.Size = strconv.FormatUint(cp.Size, 10)
	out.Hash = base64.StdEncoding.EncodeToString(cp.Hash)
	for _, l := range strings.Split(strings.TrimSuffix(string(rest), "\n"), "\n") {
		if len(rest) > 0 {
			out.Extensions = append(out.Extensions, l)
		}
	}

	if _, err := p.Verify(raw); err != nil {
		out.Error = err.Error()
	} else {
		out.Ok = true
	}
	out.Quorum = p.Satisfied(raw)

	type known struct {
		role, witness string
		alg           byte
		verifier      note.Verifier
	}
	type id struct {
		name string
		hash uint32
	}
	keys := map[id]known{}
	for _, l := range p.Logs {
		// Only a key named for this checkpoint's log signs as the log.
		if l.Verifier.Name() == cp.Origin {
			keys[id{l.Verifier.Name(), l.Verifier.KeyHash()}] = known{role: "log", alg: keyAlg(l.VKey), verifier: l.Verifier}
		}
	}
	for _, w := range p.Witnesses {
		keys[id{w.Verifier.Name(), w.Verifier.KeyHash()}] = known{role: "witness", witness: w.Name, alg: keyAlg(w.VKey), verifier: w.Verifier}
	}
	for _, s := range n.UnverifiedSigs {
		sig := signatureOut{Name: s.Name, KeyID: s.Hash, Role: "unknown", Status: "unknown-key"}
		if k, ok := keys[id{s.Name, s.Hash}]; ok {
			sig.Role, sig.Witness, sig.Alg, sig.Status = k.role, k.witness, k.alg, "invalid"
			if opened, err := note.Open(raw, note.VerifierList(k.verifier)); err == nil && len(opened.Sigs) == 1 {
				sig.Status = "valid"
				if k.role == "log" {
					out.LogSigned = true
				}
				// Cosignature keys record when they signed.
				if k.alg == 4 || k.alg == 6 {
					if t, err := f_note.CoSigV1Timestamp(opened.Sigs[0]); err == nil {
						sig.Timestamp = strconv.FormatInt(t.Unix(), 10)
					}
				}
			}
		}
		out.Signatures = append(out.Signatures, sig)
	}
	return out
}

// export registers fn as a global function from one JSON string to another.
func export[In, Out any](name string, fn func(In) Out) {
	js.Global().Set(name, js.FuncOf(func(_ js.Value, args []js.Value) any {
		var in In
		if err := json.Unmarshal([]byte(args[0].String()), &in); err != nil {
			return `{"error":"oracle: bad request: ` + err.Error() + `"}`
		}
		out, err := json.Marshal(fn(in))
		if err != nil {
			return `{"error":"oracle: ` + err.Error() + `"}`
		}
		return string(out)
	}))
}

func main() {
	export("oracleParsePolicy", func(text string) policyOut { _, out := parsePolicy(text); return out })
	export("oracleVerifyCheckpoint", verifyCheckpoint)
	export("oracleInspectCheckpoint", inspect)
	export("oracleParseProof", parseProof)
	export("oracleFormatProof", formatProof)
	export("oracleTree", tree)
	js.Global().Set("oracleReady", true)
	select {} // stay alive to serve calls
}
