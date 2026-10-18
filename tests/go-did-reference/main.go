// A test-only reference process. It has no RPC, TLS client or transaction path.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	advanced "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/sage/pkg/agent/didsource010"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
	"io"
	"os"
	"strings"
)

type reader struct {
	raw    []byte
	config registry010.Config
}

func (r reader) ReadRecord(context.Context, string) (registry010.RecordSnapshot, error) {
	h := strings.Repeat("a", 64)
	return registry010.RecordSnapshot{Source: r.config.Source, Registry: r.config.Registry, Network: r.config.Network, Record: r.raw, BlockHash: h, RecordBlockHash: h, KeysBlockHash: h, ServicesBlockHash: h, AcquiredMS: 100, Ready: true, Validated: true, Finalized: true}, nil
}

type clock struct{}

func (clock) Now() (registry010.Stamp, error) { return registry010.Stamp{MonoMS: 100, Unix: 101}, nil }
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 262145))
	must(err)
	if len(raw) > 262144 {
		panic("fixture too large")
	}
	var input struct {
		Cases []struct {
			Name   string
			Record json.RawMessage
		}
	}
	must(json.Unmarshal(raw, &input))
	dir, err := os.MkdirTemp("", "sage-did-reference-")
	must(err)
	defer os.RemoveAll(dir)
	results := map[string]any{}
	for i, c := range input.Cases {
		var record struct {
			ID, Controller, State, Version string
			Keys                           []struct {
				Name, Alg, Key, State string
				Expires               *int64
			}
			Services []struct{ Name, Type, URI string }
		}
		must(json.Unmarshal(c.Record, &record))
		d, err := did.Parse(record.ID)
		must(err)
		var r advanced.Record
		if strings.Contains(record.ID, ":eip155:") {
			config := registry010.Config{Source: "fixture-view-only-source", Registry: "eip155:11155111:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Network: "fixture-network", Blockchain: true}
			journal, err := registry010.OpenJournal(fmt.Sprintf("%s/%d", dir, i), true)
			must(err)
			src, err := didsource010.NewEIP155Source(config, reader{c.Record, config}, clock{}, journal)
			must(err)
			r, err = src.Observe(context.Background(), d)
			must(err)
			must(journal.Close())
		} else {
			// Web checks signed envelopes and typed projections, not TLS/controller/history binding.
			envelope, err := json.Marshal(map[string]any{"record": c.Record, "issued": 100, "expires": 105})
			must(err)
			must(registry010.CheckWebRegistryProofs010(envelope, record.ID, 101))
			issued := int64(100)
			r = advanced.Record{DID: d, Controller: record.Controller, State: advanced.State(record.State), Version: record.Version, Observation: advanced.Observation{Issued: &issued, Source: "fixture-view-only-source", Time: 101}}
			for _, k := range record.Keys {
				pub, err := base64.RawURLEncoding.DecodeString(k.Key)
				must(err)
				r.Keys = append(r.Keys, advanced.Key{Name: k.Name, Alg: k.Alg, Material: pub, State: advanced.KeyState(k.State), Expires: k.Expires})
			}
			for _, s := range record.Services {
				r.Services = append(r.Services, advanced.Service{Name: s.Name, Type: s.Type, URI: s.URI})
			}
		}
		views := map[string]any{}
		for name, p := range map[string]advanced.Projection{"core10": advanced.Core10, "did11": advanced.DID11} {
			doc, e := advanced.Produce(r, p, producer.New())
			if e != nil {
				panic(e)
			}
			metadata := advanced.Metadata(r)
			// Marshal the actual metadata value, including explicit false presence.
			// Rebuilding a map here would hide a missing member in MarshalJSON.
			views[name] = map[string]any{"document": string(doc), "contentType": p.MediaType(), "metadata": metadata}
		}
		results[c.Name] = views
	}
	must(json.NewEncoder(os.Stdout).Encode(results))
}
