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
	"sort"
	"syscall/js"

	f_log "github.com/transparency-dev/formats/log"
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
	export("oracleParseProof", parseProof)
	export("oracleFormatProof", formatProof)
	export("oracleTree", tree)
	js.Global().Set("oracleReady", true)
	select {} // stay alive to serve calls
}
