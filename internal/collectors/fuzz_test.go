package collectors

import (
	"strings"
	"testing"
)

// Fuzz harnesses for the hand-rolled telemetry parsers. The seed corpus runs
// under `go test`; `go test -fuzz=Fuzz...` drives the fuzzer. The contract is
// that no malformed input may panic (type assertions, fmt.Sprint, etc.).

var nastySeeds = []string{
	"",
	"\n\n\n",
	"not json at all",
	`{"a":`,
	`{"nested":{"deep":{"deeper":[1,2,3,{"x":null}]}}}`,
	`{"src_ip":1234,"dest_port":"not-a-number","flow":[]}`,
	`{"event_type":null,"alert":{"signature":12345}}`,
	`{"key":["a",["b",["c"]]]}`,
	`[]`,
	`123`,
	`true`,
}

func FuzzNormalizeSuricataEVE(f *testing.F) {
	f.Add(`{"event_type":"alert","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","alert":{"signature":"x"}}`)
	for _, s := range nastySeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = normalizeSuricataEVE(strings.NewReader(data))
	})
}

func FuzzNormalizeSysmonJSON(f *testing.F) {
	f.Add(`{"EventID":1,"Image":"C:/x.exe","CommandLine":"x"}`)
	for _, s := range nastySeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = normalizeSysmonJSON(strings.NewReader(data))
	})
}

func FuzzNormalizeAuditd(f *testing.F) {
	f.Add(`type=SYSCALL msg=audit(1.1:1): a0=1 exe="/bin/sh"` + "\n")
	for _, s := range nastySeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = normalizeAuditd(strings.NewReader(data))
	})
}

func FuzzNormalizeZeekConn(f *testing.F) {
	f.Add("#fields\tts\tid.orig_h\tid.resp_h\n1\t1.2.3.4\t5.6.7.8\n")
	f.Add(`{"id.orig_h":"1.2.3.4","id.resp_h":"5.6.7.8"}`)
	for _, s := range nastySeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = normalizeZeekConn(strings.NewReader(data))
	})
}
