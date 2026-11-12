//go:build wasm

// Command verifier is the part of the viewer that understands transparency
// log formats. It is the Go implementations themselves, compiled to
// WebAssembly and called from the page: github.com/transparency-dev/formats
// for policies, signed checkpoints, cosignatures and proofs, and
// golang.org/x/mod/sumdb/tlog for the Merkle tree.
//
// What is written here is only the questions the page asks of them and the
// shape of the answers. Each exported function takes a JSON string, or bytes
// and numbers where the input is large, and returns a JSON string, or bytes
// where that is what was asked for.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall/js"

	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/formats/policy"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// The signature type bytes that begin a verifier key, and their names.
const (
	algEd25519      = 0x01
	algEd25519Cosig = 0x04
	algMLDSA44      = 0x06
)

func algName(alg byte) string {
	switch alg {
	case algEd25519:
		return "Ed25519"
	case 0x02:
		return "ECDSA"
	case algEd25519Cosig:
		return "Ed25519 cosignature"
	case 0x05:
		return "RFC 6962"
	case algMLDSA44:
		return "ML-DSA-44"
	}
	return fmt.Sprintf("type 0x%02x", alg)
}

// keyAlg returns the signature type byte of a vkey the policy parser accepted.
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

// ---------------------------------------------------------------------------
// Policies

type keyOut struct {
	// Name is the key's name: for a log, its origin.
	Name  string `json:"name"`
	KeyID uint32 `json:"keyId"`
	Alg   string `json:"alg"`
	VKey  string `json:"vkey"`
	// Witness is the policy's own name for a witness.
	Witness string `json:"witness,omitempty"`
}

type groupOut struct {
	Name      string   `json:"name"`
	Threshold uint     `json:"threshold"`
	Members   []string `json:"members"`
}

type policyOut struct {
	Error string `json:"error,omitempty"`
	// Origins are the distinct logs the policy trusts, in order of first mention.
	Origins   []string   `json:"origins"`
	Logs      []keyOut   `json:"logs"`
	Witnesses []keyOut   `json:"witnesses"`
	Groups    []groupOut `json:"groups"`
	Quorum    string     `json:"quorum"`
}

func parsePolicy(text string) (*policy.TLogPolicy, policyOut) {
	p := &policy.TLogPolicy{}
	if err := p.Unmarshal([]byte(text)); err != nil {
		return nil, policyOut{Error: err.Error()}
	}
	out := policyOut{Origins: []string{}, Logs: []keyOut{}, Witnesses: []keyOut{}, Groups: []groupOut{}, Quorum: p.Quorum}
	seen := map[string]bool{}
	for _, l := range p.Logs {
		name := l.Verifier.Name()
		if !seen[name] {
			seen[name] = true
			out.Origins = append(out.Origins, name)
		}
		out.Logs = append(out.Logs, keyOut{Name: name, KeyID: l.Verifier.KeyHash(), Alg: algName(keyAlg(l.VKey)), VKey: l.VKey})
	}
	for _, w := range p.Witnesses {
		out.Witnesses = append(out.Witnesses, keyOut{Name: w.Verifier.Name(), KeyID: w.Verifier.KeyHash(), Alg: algName(keyAlg(w.VKey)), VKey: w.VKey, Witness: w.Name})
	}
	for _, g := range p.Groups {
		out.Groups = append(out.Groups, groupOut{Name: g.Name, Threshold: g.Threshold, Members: g.Members})
	}
	return p, out
}

// quorumNode is the quorum rule, evaluated: what the page draws as a tree.
type quorumNode struct {
	Name string `json:"name"`
	// Kind is "witness", "group", or "none" for a policy requiring no cosignatures.
	Kind      string       `json:"kind"`
	Satisfied bool         `json:"satisfied"`
	Threshold uint         `json:"threshold,omitempty"`
	Count     uint         `json:"count"`
	Children  []quorumNode `json:"children,omitempty"`
}

// evalQuorum works out which parts of the quorum rule a set of witnesses
// meets. formats answers only yes or no for a whole checkpoint
// (TLogPolicy.Satisfied); the page also shows why. Callers check the answer
// at the root against Satisfied.
func evalQuorum(p *policy.TLogPolicy, valid map[string]bool) quorumNode {
	if p.Quorum == "none" {
		return quorumNode{Name: "none", Kind: "none", Satisfied: true}
	}
	groups := map[string]policy.Group{}
	for _, g := range p.Groups {
		groups[g.Name] = g
	}
	var eval func(name string) quorumNode
	eval = func(name string) quorumNode {
		g, ok := groups[name]
		if !ok {
			return quorumNode{Name: name, Kind: "witness", Satisfied: valid[name]}
		}
		n := quorumNode{Name: name, Kind: "group", Threshold: g.Threshold}
		for _, m := range g.Members {
			c := eval(m)
			if c.Satisfied {
				n.Count++
			}
			n.Children = append(n.Children, c)
		}
		n.Satisfied = n.Count >= g.Threshold
		return n
	}
	return eval(p.Quorum)
}

// ---------------------------------------------------------------------------
// Checkpoints

type signatureOut struct {
	Name  string `json:"name"`
	KeyID uint32 `json:"keyId"`
	// Role is "log", "witness", or "unknown" for a key outside the policy.
	Role string `json:"role"`
	// Witness is the policy's name for a witness.
	Witness string `json:"witness,omitempty"`
	Alg     string `json:"alg,omitempty"`
	// Status is "valid", "invalid" or "unknown-key".
	Status string `json:"status"`
	// Timestamp is a valid cosignature's time, in decimal Unix seconds.
	Timestamp string `json:"timestamp,omitempty"`
}

type checkpointIn struct {
	Policy     string `json:"policy"`
	Checkpoint string `json:"checkpoint"`
	// ExpectedOrigin, if set, is the log the checkpoint was fetched as.
	ExpectedOrigin string `json:"expectedOrigin"`
}

type checkpointOut struct {
	// Malformed is set, and nothing else, if the input is not a signed
	// checkpoint under a readable policy at all.
	Malformed string `json:"malformed,omitempty"`
	// Ok is whether the checkpoint may be relied on: the policy's verdict
	// (TLogPolicy.Verify) for the log it was fetched as.
	Ok bool `json:"ok"`
	// Problems are the reasons it may not be; Warnings, anomalies that do not
	// change the verdict, such as a bad signature beside good ones.
	Problems []string `json:"problems"`
	Warnings []string `json:"warnings"`
	// Text is the signed text of the note.
	Text       string   `json:"text"`
	Origin     string   `json:"origin"`
	Size       string   `json:"size"`
	Hash       string   `json:"hash"`
	Extensions []string `json:"extensions"`
	// Signatures are the note's signature lines, in order.
	Signatures []signatureOut `json:"signatures"`
	LogSigned  bool           `json:"logSigned"`
	Quorum     quorumNode     `json:"quorum"`
	// WitnessedAt is when the quorum was reached, in decimal Unix seconds:
	// the latest time such that the cosignatures made at or after it are
	// enough on their own.
	WitnessedAt string `json:"witnessedAt,omitempty"`
	// ExtensionsAuthenticated is false if there are extension lines and no
	// valid log signature that covers the note's text.
	ExtensionsAuthenticated bool `json:"extensionsAuthenticated"`
}

func verifyCheckpoint(in checkpointIn) checkpointOut {
	p, parsed := parsePolicy(in.Policy)
	if p == nil {
		return checkpointOut{Malformed: "the trust policy cannot be read: " + parsed.Error}
	}
	raw := []byte(in.Checkpoint)

	// Opening a note with no known keys fails in a way that hands back the
	// parsed note, signature lines included.
	_, err := note.Open(raw, note.VerifierList())
	var unverified *note.UnverifiedNoteError
	if !errors.As(err, &unverified) {
		if err == nil {
			err = errors.New("not a signed note")
		}
		return checkpointOut{Malformed: err.Error()}
	}
	n := unverified.Note
	var cp f_log.Checkpoint
	rest, err := cp.Unmarshal([]byte(n.Text))
	if err != nil {
		return checkpointOut{Malformed: err.Error()}
	}
	out := checkpointOut{
		Problems: []string{}, Warnings: []string{}, Extensions: []string{}, Signatures: []signatureOut{},
		Text: n.Text, Origin: cp.Origin, Size: strconv.FormatUint(cp.Size, 10), Hash: base64.StdEncoding.EncodeToString(cp.Hash),
	}
	if len(rest) > 0 {
		out.Extensions = strings.Split(strings.TrimSuffix(string(rest), "\n"), "\n")
	}

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
	originKnown := false
	for _, l := range p.Logs {
		// Only a key named for this checkpoint's log signs as the log.
		if l.Verifier.Name() == cp.Origin {
			originKnown = true
			keys[id{l.Verifier.Name(), l.Verifier.KeyHash()}] = known{role: "log", alg: keyAlg(l.VKey), verifier: l.Verifier}
		}
	}
	for _, w := range p.Witnesses {
		keys[id{w.Verifier.Name(), w.Verifier.KeyHash()}] = known{role: "witness", witness: w.Name, alg: keyAlg(w.VKey), verifier: w.Verifier}
	}

	valid := map[string]bool{}
	cosignedAt := map[string]int64{}
	textSigned := false
	for _, s := range n.UnverifiedSigs {
		sig := signatureOut{Name: s.Name, KeyID: s.Hash, Role: "unknown", Status: "unknown-key"}
		if k, ok := keys[id{s.Name, s.Hash}]; ok {
			sig.Role, sig.Witness, sig.Alg, sig.Status = k.role, k.witness, algName(k.alg), "invalid"
			if opened, err := note.Open(raw, note.VerifierList(k.verifier)); err == nil && len(opened.Sigs) == 1 {
				sig.Status = "valid"
				if k.role == "log" {
					out.LogSigned = true
					// An ML-DSA signature covers the origin, size and root,
					// not the note's text.
					textSigned = textSigned || k.alg != algMLDSA44
				} else {
					valid[k.witness] = true
				}
				if k.alg == algEd25519Cosig || k.alg == algMLDSA44 {
					if t, err := f_note.CoSigV1Timestamp(opened.Sigs[0]); err == nil {
						sig.Timestamp = strconv.FormatInt(t.Unix(), 10)
						if k.role == "witness" {
							cosignedAt[k.witness] = t.Unix()
						}
					}
				}
			} else {
				out.Warnings = append(out.Warnings, fmt.Sprintf("invalid signature from %s (%s)", s.Name, sig.Alg))
			}
		}
		out.Signatures = append(out.Signatures, sig)
	}
	out.ExtensionsAuthenticated = len(out.Extensions) == 0 || textSigned

	// The verdict is the policy's. The reasons given for a refusal are worked
	// out here, and must come to the same conclusion.
	_, verifyErr := p.Verify(raw)
	out.Quorum = evalQuorum(p, valid)
	if out.Quorum.Satisfied != p.Satisfied(raw) {
		return checkpointOut{Malformed: "internal error: the quorum shown would differ from the policy's verdict"}
	}
	if in.ExpectedOrigin != "" && cp.Origin != in.ExpectedOrigin {
		out.Problems = append(out.Problems, fmt.Sprintf("checkpoint is for %s, not %s", cp.Origin, in.ExpectedOrigin))
	}
	if !originKnown {
		out.Problems = append(out.Problems, fmt.Sprintf("origin %s is not a log in the policy", cp.Origin))
	} else if !out.LogSigned {
		out.Problems = append(out.Problems, "no valid signature from a log key in the policy")
	}
	if !out.Quorum.Satisfied {
		out.Problems = append(out.Problems, "witness quorum not met")
	}
	if verifyErr != nil && len(out.Problems) == 0 {
		out.Problems = append(out.Problems, verifyErr.Error())
	}
	out.Ok = verifyErr == nil && len(out.Problems) == 0

	if out.Quorum.Satisfied && p.Quorum != "none" {
		// Add cosigners newest first until they meet the quorum by themselves.
		names := make([]string, 0, len(cosignedAt))
		for name := range cosignedAt {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool {
			if cosignedAt[names[i]] != cosignedAt[names[j]] {
				return cosignedAt[names[i]] > cosignedAt[names[j]]
			}
			return names[i] < names[j]
		})
		recent := map[string]bool{}
		for _, name := range names {
			recent[name] = true
			if evalQuorum(p, recent).Satisfied {
				out.WitnessedAt = strconv.FormatInt(cosignedAt[name], 10)
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Where a log keeps things (c2sp.org/tlog-tiles)

// tileRef is a level-0 tile of a log and the entry bundle beside it.
type tileRef struct {
	Index uint64 `json:"index"`
	// Width is the number of hashes in the tile, and of entries in the bundle.
	Width uint `json:"width"`
	// First is the index in the log of the tile's first leaf.
	First uint64 `json:"first"`
	// Path and Entries are where the tile and its entry bundle are served,
	// relative to the log's URL.
	Path    string `json:"path"`
	Entries string `json:"entries"`
}

type layoutIn struct {
	// From and Size are tree sizes: the leaves wanted are those from From up
	// to Size.
	From uint64 `json:"from"`
	Size uint64 `json:"size"`
}

type layoutOut struct {
	// Checkpoint is where the log serves its checkpoint.
	Checkpoint string `json:"checkpoint"`
	// Tiles are those holding the leaves wanted, in order. The first also
	// holds earlier leaves unless From is the start of a tile.
	Tiles []tileRef `json:"tiles"`
}

func tileLayout(in layoutIn) layoutOut {
	out := layoutOut{Checkpoint: layout.CheckpointPath, Tiles: []tileRef{}}
	if in.From >= in.Size {
		return out
	}
	for r := range layout.Range(in.From, in.Size-in.From, in.Size) {
		width := uint(r.Partial)
		if width == 0 {
			width = layout.TileWidth
		}
		out.Tiles = append(out.Tiles, tileRef{
			Index: r.Index, Width: width, First: r.Index * layout.TileWidth,
			Path: layout.TilePath(0, r.Index, r.Partial), Entries: layout.EntriesPath(r.Index, r.Partial),
		})
	}
	return out
}

// splitBundle returns the entries of an entry bundle.
func splitBundle(raw []byte) ([][]byte, error) {
	var b api.EntryBundle
	if err := b.UnmarshalText(raw); err != nil {
		return nil, err
	}
	return b.Entries, nil
}

// ---------------------------------------------------------------------------
// The Merkle tree

// stored is tlog's stored-hash sequence for a tree, built from leaf hashes.
type stored []tlog.Hash

func (s stored) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 || x >= int64(len(s)) {
			return nil, fmt.Errorf("hash %d is outside the tree", x)
		}
		out[i] = s[x]
	}
	return out, nil
}

func storedHashes(leaves []byte, size int64) (stored, error) {
	if size < 0 || int64(len(leaves)) < size*tlog.HashSize {
		return nil, errors.New("fewer leaf hashes than the tree size")
	}
	var s stored
	for i := int64(0); i < size; i++ {
		var h tlog.Hash
		copy(h[:], leaves[i*tlog.HashSize:])
		hs, err := tlog.StoredHashesForRecordHash(i, h, s)
		if err != nil {
			return nil, err
		}
		s = append(s, hs...)
	}
	return s, nil
}

type tileOut struct {
	Level int    `json:"level"`
	Index int64  `json:"index"`
	Width int    `json:"width"`
	Data  string `json:"data"` // hex
	// Path is where the log serves the tile, relative to its URL.
	Path string `json:"path"`
}

type treeOut struct {
	Error string `json:"error,omitempty"`
	Root  string `json:"root"` // base64, as in a checkpoint
	// Interior is what the log's tiles above level 0 must contain.
	Interior []tileOut `json:"interior"`
}

// tree hashes the tree of the first size leaf hashes.
func tree(leaves []byte, size int64) treeOut {
	s, err := storedHashes(leaves, size)
	if err != nil {
		return treeOut{Error: err.Error()}
	}
	root, err := tlog.TreeHash(size, s)
	if err != nil {
		return treeOut{Error: err.Error()}
	}
	if size == 0 {
		// RFC 6962: the head of an empty tree is the hash of nothing. tlog
		// leaves it as zeros.
		root = tlog.Hash(sha256.Sum256(nil))
	}
	out := treeOut{Root: base64.StdEncoding.EncodeToString(root[:]), Interior: []tileOut{}}
	for _, t := range tlog.NewTiles(layout.TileHeight, 0, size) {
		if t.L < 1 {
			continue
		}
		data, err := tlog.ReadTileData(t, s)
		if err != nil {
			return treeOut{Error: err.Error()}
		}
		partial := uint8(0)
		if t.W < layout.TileWidth {
			partial = uint8(t.W)
		}
		out.Interior = append(out.Interior, tileOut{
			Level: t.L, Index: t.N, Width: t.W, Data: hex.EncodeToString(data),
			Path: layout.TilePath(uint64(t.L), uint64(t.N), partial),
		})
	}
	return out
}

type proofOut struct {
	Error string `json:"error,omitempty"`
	// Proof is a c2sp.org/tlog-proof.
	Proof string `json:"proof,omitempty"`
}

// proveInclusion writes the tlog-proof for one leaf: its inclusion proof and
// the signed checkpoint the proof leads to.
func proveInclusion(leaves []byte, size, index int64, checkpoint string) proofOut {
	s, err := storedHashes(leaves, size)
	if err != nil {
		return proofOut{Error: err.Error()}
	}
	rp, err := tlog.ProveRecord(size, index, s)
	if err != nil {
		return proofOut{Error: err.Error()}
	}
	pr := proof.TLogProof{Index: uint64(index), Checkpoint: []byte(checkpoint)}
	for _, h := range rp {
		pr.Hashes = append(pr.Hashes, [32]byte(h))
	}
	return proofOut{Proof: string(pr.Marshal())}
}

type checkProofIn struct {
	Policy string `json:"policy"`
	Proof  string `json:"proof"`
	// LeafHash is the hash of the entry the proof is offered for, in hex.
	LeafHash string `json:"leafHash"`
}

type checkProofOut struct {
	Error  string `json:"error,omitempty"`
	Ok     bool   `json:"ok"`
	Index  uint64 `json:"index"`
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
}

// checkProof is what someone handed a tlog-proof does with it: checks its
// checkpoint against a policy, and the entry against the checkpoint.
func checkProof(in checkProofIn) checkProofOut {
	p, parsed := parsePolicy(in.Policy)
	if p == nil {
		return checkProofOut{Error: parsed.Error}
	}
	var pr proof.TLogProof
	if err := pr.Unmarshal([]byte(in.Proof)); err != nil {
		return checkProofOut{Error: err.Error()}
	}
	cp, err := p.Verify(pr.Checkpoint)
	if err != nil {
		return checkProofOut{Error: err.Error()}
	}
	leaf, err := hex.DecodeString(in.LeafHash)
	if err != nil || len(leaf) != tlog.HashSize || len(cp.Hash) != tlog.HashSize {
		return checkProofOut{Error: "bad hash"}
	}
	var rp tlog.RecordProof
	for _, h := range pr.Hashes {
		rp = append(rp, tlog.Hash(h))
	}
	out := checkProofOut{Index: pr.Index, Origin: cp.Origin, Size: cp.Size}
	if err := tlog.CheckRecord(rp, int64(cp.Size), tlog.Hash(cp.Hash), int64(pr.Index), tlog.Hash(leaf)); err != nil {
		out.Error = err.Error()
		return out
	}
	out.Ok = true
	return out
}

// ---------------------------------------------------------------------------
// The JavaScript boundary

func reply(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		return `{"error":"verifier: ` + err.Error() + `"}`
	}
	return string(out)
}

// export registers fn as a global function from one JSON string to another.
func export[In, Out any](name string, fn func(In) Out) {
	js.Global().Set(name, js.FuncOf(func(_ js.Value, args []js.Value) any {
		var in In
		if err := json.Unmarshal([]byte(args[0].String()), &in); err != nil {
			return `{"error":"verifier: bad request: ` + err.Error() + `"}`
		}
		return reply(fn(in))
	}))
}

// bytesArg copies a Uint8Array argument.
func bytesArg(v js.Value) []byte {
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

// bytesValue copies bytes into a new Uint8Array.
func bytesValue(b []byte) js.Value {
	v := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(v, b)
	return v
}

func main() {
	export("tlogPolicy", func(text string) policyOut { _, out := parsePolicy(text); return out })
	export("tlogCheckpoint", verifyCheckpoint)
	export("tlogCheckProof", checkProof)
	// Leaf hashes are passed as bytes: there may be millions.
	js.Global().Set("tlogTree", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return reply(tree(bytesArg(args[0]), int64(args[1].Int())))
	}))
	js.Global().Set("tlogProve", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return reply(proveInclusion(bytesArg(args[0]), int64(args[1].Int()), int64(args[2].Int()), args[3].String()))
	}))
	export("tlogLayout", tileLayout)
	// Bundles and entries are passed as bytes too, and come back as bytes.
	js.Global().Set("tlogBundle", js.FuncOf(func(_ js.Value, args []js.Value) any {
		entries, err := splitBundle(bytesArg(args[0]))
		if err != nil {
			return reply(map[string]string{"error": err.Error()})
		}
		out := make([]any, len(entries))
		for i, e := range entries {
			out[i] = bytesValue(e)
		}
		return js.ValueOf(out)
	}))
	js.Global().Set("tlogLeafHash", js.FuncOf(func(_ js.Value, args []js.Value) any {
		h := tlog.RecordHash(bytesArg(args[0]))
		return bytesValue(h[:])
	}))
	js.Global().Set("tlogReady", true)
	select {} // stay alive to serve calls
}
