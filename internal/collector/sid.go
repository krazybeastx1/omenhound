package collector

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// FormatSID converts a binary Windows SID to its canonical string form, e.g.
// []byte{1,5,0,0,0,0,0,5,21,0,0,0} -> "S-1-5-21".
//
// objectSid is returned by LDAP as raw bytes; every OmenHound node is keyed by
// this string so identities are stable and domain-unique.
func FormatSID(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("sid: too short (%d bytes)", len(b))
	}
	revision := b[0]
	subCount := int(b[1])
	if len(b) < 8+4*subCount {
		return "", fmt.Errorf("sid: truncated (need %d, have %d)", 8+4*subCount, len(b))
	}
	var authority uint64
	for _, x := range b[2:8] {
		authority = authority<<8 | uint64(x)
	}
	parts := make([]string, 0, subCount+2)
	parts = append(parts, fmt.Sprintf("S-%d-%d", revision, authority))
	for i := 0; i < subCount; i++ {
		sub := binary.LittleEndian.Uint32(b[8+i*4 : 12+i*4])
		parts = append(parts, fmt.Sprintf("%d", sub))
	}
	return strings.Join(parts, "-"), nil
}

// DomainToDN converts "corp.local" to "DC=corp,DC=local".
func DomainToDN(domain string) string {
	domain = strings.Trim(domain, ".")
	if domain == "" {
		return ""
	}
	segs := strings.Split(domain, ".")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		if s == "" {
			continue
		}
		out = append(out, "DC="+s)
	}
	return strings.Join(out, ",")
}
