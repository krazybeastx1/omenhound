package collector

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Windows security descriptors
//
// LDAP returns the nTSecurityDescriptor attribute as a self-relative
// SECURITY_DESCRIPTOR ([MS-DTYP] 2.4.6). OmenHound parses the owner and the
// discretionary ACL so the ACL collector can turn ACEs into BloodHound-style
// edges, mirroring BloodHound.py's ACLProcessor.
// ---------------------------------------------------------------------------

// GUID is a 16-byte Windows GUID in its on-the-wire (little-endian) layout.
type GUID [16]byte

// String renders the GUID in registry form, e.g.
// "00299570-246d-11d0-a768-00aa006e0529". The first three components are
// stored little-endian on the wire; the last two are big-endian.
func (g GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%s-%s",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		hex.EncodeToString(g[8:10]),
		hex.EncodeToString(g[10:16]))
}

// ParseGUID parses a registry-form GUID string into its wire layout.
func ParseGUID(s string) (GUID, error) {
	var g GUID
	s = strings.Trim(strings.TrimSpace(s), "{}")
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return g, fmt.Errorf("guid: %q: want 5 dash-separated components", s)
	}
	want := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != want[i] {
			return g, fmt.Errorf("guid: %q: component %d has %d chars, want %d", s, i, len(p), want[i])
		}
	}
	d1, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return g, fmt.Errorf("guid: %q: %w", s, err)
	}
	d2, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return g, fmt.Errorf("guid: %q: %w", s, err)
	}
	d3, err := strconv.ParseUint(parts[2], 16, 16)
	if err != nil {
		return g, fmt.Errorf("guid: %q: %w", s, err)
	}
	d4, err := hex.DecodeString(parts[3])
	if err != nil {
		return g, fmt.Errorf("guid: %q: %w", s, err)
	}
	d5, err := hex.DecodeString(parts[4])
	if err != nil {
		return g, fmt.Errorf("guid: %q: %w", s, err)
	}
	binary.LittleEndian.PutUint32(g[0:4], uint32(d1))
	binary.LittleEndian.PutUint16(g[4:6], uint16(d2))
	binary.LittleEndian.PutUint16(g[6:8], uint16(d3))
	copy(g[8:10], d4)
	copy(g[10:16], d5)
	return g, nil
}

// mustGUID is for compile-time-known constants; it panics on a malformed
// literal, which can only be a programming error.
func mustGUID(s string) GUID {
	g, err := ParseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}

// Security-descriptor control bits (Win32 SECURITY_DESCRIPTOR_CONTROL). A
// self-relative descriptor with a DACL, which is what LDAP always returns, has
// 0x8004 in this field.
const (
	sdControlDACLProtected = 0x1000 // SE_DACL_PROTECTED
	sdControlSelfRelative  = 0x8000 // SE_SELF_RELATIVE
)

// ACE_HEADER AceFlags bits ([MS-DTYP] 2.4.4.1).
const (
	aceFlagInheritOnly = 0x08
	aceFlagInherited   = 0x10
)

// Access-mask bits ([MS-DTYP] 2.4.3) used by the ACE mapper. The generic masks
// are AD's interpretation of the generic rights ([MS-ADTS] 5.1.3.2).
const (
	maskGenericAll      = 0x000F01FF
	maskGenericWrite    = 0x00020028
	maskWriteOwner      = 0x00080000
	maskWriteDACL       = 0x00040000
	maskDSSelf          = 0x00000008
	maskDSReadProp      = 0x00000010
	maskDSWriteProp     = 0x00000020
	maskDSControlAccess = 0x00000100
)

// ACE types the mapper understands. Everything else is counted and skipped.
const (
	aceTypeAccessAllowed       = 0x00
	aceTypeAccessAllowedObject = 0x05
)

// ACE-object flag bits for ACCESS_ALLOWED_OBJECT_ACE ([MS-DTYP] 2.4.4.3).
const (
	aceObjectTypePresent          = 0x01
	aceInheritedObjectTypePresent = 0x02
	aceObjectBodyHeader           = 8 // AceType+AceFlags+AceSize+Mask
)

// ACE is a parsed access-control entry. ObjectType/InheritedObjectType are nil
// when the corresponding presence flag is not set.
type ACE struct {
	Type                uint8
	Flags               uint8
	Mask                uint32
	ObjectType          *GUID
	InheritedObjectType *GUID
	SID                 string
}

func (a ACE) inherited() bool { return a.Flags&aceFlagInherited != 0 }
func (a ACE) inheritOnly() bool {
	return a.Flags&aceFlagInheritOnly != 0
}

// SecurityDescriptor is the parsed subset of a Windows SECURITY_DESCRIPTOR that
// the ACL collector needs: the owner and the discretionary ACL.
type SecurityDescriptor struct {
	Control  uint16
	OwnerSID string
	DACL     []ACE
	// DACLProtected reports SE_DACL_PROTECTED, i.e. inherited ACEs are blocked.
	DACLProtected bool
	// RawACECount is the count from the ACL header, before type filtering.
	RawACECount int
}

// ParseSecurityDescriptor parses a self-relative SECURITY_DESCRIPTOR.
//
// Only the owner and the DACL are extracted; the group and the SACL are not
// needed to build attack paths. ACE types other than access-allowed and
// access-allowed-object are still returned (with an empty body) so the caller
// can count and report them rather than silently dropping them.
func ParseSecurityDescriptor(b []byte) (*SecurityDescriptor, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("sd: too short (%d bytes, need 20)", len(b))
	}
	control := binary.LittleEndian.Uint16(b[2:4])
	if control&sdControlSelfRelative == 0 {
		// Absolute descriptors carry memory pointers, not offsets; parsing one
		// as self-relative would silently produce garbage. LDAP never returns
		// one, so this is a guard rather than a case handled.
		return nil, fmt.Errorf("sd: descriptor is not self-relative (control 0x%04x)", control)
	}
	offOwner := int(binary.LittleEndian.Uint32(b[4:8]))
	offDACL := int(binary.LittleEndian.Uint32(b[16:20]))

	sd := &SecurityDescriptor{
		Control:       control,
		DACLProtected: control&sdControlDACLProtected != 0,
	}
	if offOwner != 0 {
		if offOwner >= len(b) {
			return nil, fmt.Errorf("sd: owner offset %d out of range (len %d)", offOwner, len(b))
		}
		sid, err := FormatSID(b[offOwner:])
		if err != nil {
			return nil, fmt.Errorf("sd: owner: %w", err)
		}
		sd.OwnerSID = sid
	}
	if offDACL != 0 {
		if offDACL >= len(b) {
			return nil, fmt.Errorf("sd: dacl offset %d out of range (len %d)", offDACL, len(b))
		}
		aces, count, err := parseACL(b[offDACL:])
		if err != nil {
			return nil, err
		}
		sd.DACL = aces
		sd.RawACECount = count
	}
	return sd, nil
}

// parseACL walks an ACL structure ([MS-DTYP] 2.4.5) and returns its ACEs plus
// the header's ACE count.
func parseACL(b []byte) ([]ACE, int, error) {
	if len(b) < 8 {
		return nil, 0, fmt.Errorf("sd: acl too short (%d bytes, need 8)", len(b))
	}
	aclSize := int(binary.LittleEndian.Uint16(b[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(b[4:6]))
	if aclSize < 8 {
		return nil, 0, fmt.Errorf("sd: acl size %d is below the 8-byte header", aclSize)
	}
	if aclSize > len(b) {
		// The descriptor is self-relative; a trailing short read just means we
		// were handed a truncated buffer. Parse what is present.
		aclSize = len(b)
	}
	body := b[8:aclSize]

	aces := make([]ACE, 0, aceCount)
	pos := 0
	for i := 0; i < aceCount; i++ {
		if pos+4 > len(body) {
			return nil, aceCount, fmt.Errorf("sd: acl truncated before ace %d of %d", i, aceCount)
		}
		aceType := body[pos]
		aceFlags := body[pos+1]
		aceSize := int(binary.LittleEndian.Uint16(body[pos+2 : pos+4]))
		if aceSize < 4 || pos+aceSize > len(body) {
			return nil, aceCount, fmt.Errorf("sd: ace %d has invalid size %d", i, aceSize)
		}
		raw := body[pos : pos+aceSize]
		pos += aceSize

		switch aceType {
		case aceTypeAccessAllowed, aceTypeAccessAllowedObject:
			ace, err := parseACE(aceType, aceFlags, raw)
			if err != nil {
				return nil, aceCount, fmt.Errorf("sd: ace %d: %w", i, err)
			}
			aces = append(aces, ace)
		default:
			// Denied/audit/resource-attribute/... ACEs: record the header so
			// the mapper can count them, but do not interpret the body.
			aces = append(aces, ACE{Type: aceType, Flags: aceFlags})
		}
	}
	return aces, aceCount, nil
}

func parseACE(aceType, aceFlags uint8, b []byte) (ACE, error) {
	ace := ACE{Type: aceType, Flags: aceFlags}
	if len(b) < aceObjectBodyHeader {
		return ace, fmt.Errorf("body too short (%d bytes)", len(b))
	}
	ace.Mask = binary.LittleEndian.Uint32(b[4:8])
	rest := b[8:]

	if aceType == aceTypeAccessAllowedObject {
		if len(rest) < 4 {
			return ace, fmt.Errorf("object ace missing flags")
		}
		oflags := binary.LittleEndian.Uint32(rest[0:4])
		rest = rest[4:]
		if oflags&aceObjectTypePresent != 0 {
			if len(rest) < 16 {
				return ace, fmt.Errorf("object ace missing object type")
			}
			var g GUID
			copy(g[:], rest[:16])
			ace.ObjectType = &g
			rest = rest[16:]
		}
		if oflags&aceInheritedObjectTypePresent != 0 {
			if len(rest) < 16 {
				return ace, fmt.Errorf("object ace missing inherited object type")
			}
			var g GUID
			copy(g[:], rest[:16])
			ace.InheritedObjectType = &g
			rest = rest[16:]
		}
	}
	sid, err := FormatSID(rest)
	if err != nil {
		return ace, fmt.Errorf("sid: %w", err)
	}
	ace.SID = sid
	return ace, nil
}
