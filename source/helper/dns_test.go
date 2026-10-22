// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var syntheticRange = netip.MustParsePrefix("198.18.0.0/15")

func buildQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		// A name the library refuses is sent as raw bytes, so the server's own validation is tested.
		return rawQuery(name, qtype)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rawQuery packs a question whose name is written label by label, with no check on the bytes.
func rawQuery(name string, qtype dnsmessage.Type) []byte {
	b := []byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b
}

func parseAnswer(t *testing.T, raw []byte) dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatalf("the answer does not parse: %v", err)
	}
	return msg
}

func addressOf(t *testing.T, msg dnsmessage.Message) netip.Addr {
	t.Helper()
	if len(msg.Answers) != 1 {
		t.Fatalf("want one answer, got %d (rcode %v)", len(msg.Answers), msg.Header.RCode)
	}
	a, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("want an A record, got %T", msg.Answers[0].Body)
	}
	return netip.AddrFrom4(a.A)
}

func TestLookupTwiceSameAddress(t *testing.T) {
	m := newNameMap(nil, 0)
	first := addressOf(t, parseAnswer(t, m.answer(buildQuery(t, "api.example.org.", dnsmessage.TypeA))))
	second := addressOf(t, parseAnswer(t, m.answer(buildQuery(t, "api.example.org.", dnsmessage.TypeA))))
	if first != second {
		t.Fatalf("two lookups of one name gave %v and %v", first, second)
	}
	if !syntheticRange.Contains(first) {
		t.Fatalf("%v is not in %v", first, syntheticRange)
	}
	name, ok := m.nameFor(first)
	if !ok || name != "api.example.org" {
		t.Fatalf("the map gives %q, %v for %v", name, ok, first)
	}
}

func TestTwoNamesGetTwoAddressesAndNeverTheTunnelAddress(t *testing.T) {
	m := newNameMap(nil, 0)
	seen := map[netip.Addr]string{}
	for _, name := range []string{"a.example.org.", "b.example.org.", "c.example.org."} {
		addr := addressOf(t, parseAnswer(t, m.answer(buildQuery(t, name, dnsmessage.TypeA))))
		if other, dup := seen[addr]; dup {
			t.Fatalf("%s and %s share %v", name, other, addr)
		}
		seen[addr] = name
		if addr == netip.MustParseAddr("198.18.0.1") || addr == netip.MustParseAddr("198.18.0.0") {
			t.Fatalf("%s got the reserved address %v", name, addr)
		}
	}
}

func TestNameIsLowercasedAndTheTrailingDotIsStripped(t *testing.T) {
	m := newNameMap(nil, 0)
	upper := addressOf(t, parseAnswer(t, m.answer(buildQuery(t, "API.Example.ORG.", dnsmessage.TypeA))))
	lower := addressOf(t, parseAnswer(t, m.answer(buildQuery(t, "api.example.org.", dnsmessage.TypeA))))
	if upper != lower {
		t.Fatalf("%v != %v", upper, lower)
	}
	if name, _ := m.nameFor(upper); name != "api.example.org" {
		t.Fatalf("got %q", name)
	}
}

func TestAAAAAndOtherTypesGetAnEmptyAnswer(t *testing.T) {
	m := newNameMap(nil, 0)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeTXT, dnsmessage.TypeSRV, dnsmessage.TypeMX, dnsmessage.TypePTR} {
		msg := parseAnswer(t, m.answer(buildQuery(t, "api.example.org.", qtype)))
		if msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Answers) != 0 {
			t.Fatalf("type %v: rcode %v with %d answers", qtype, msg.Header.RCode, len(msg.Answers))
		}
	}
}

func TestAnUnmappedAddressHasNoName(t *testing.T) {
	m := newNameMap(nil, 0)
	if name, ok := m.nameFor(netip.MustParseAddr("198.18.9.9")); ok {
		t.Fatalf("got %q for an address the server never handed out", name)
	}
}

func TestANameWithABadByteGetsFormErr(t *testing.T) {
	m := newNameMap(nil, 0)
	bad := []string{
		"a b.example.org.", "a\r.example.org.", "a\n.example.org.", "a:80.example.org.", "a\x00.example.org.",
		"a/b.example.org.", "a@b.example.org.", "ü.example.org.",
		strings.Repeat("a", 64) + ".example.org.",
		strings.Repeat("abcdefghi.", 26) + "org.",
	}
	for _, name := range bad {
		msg := parseAnswer(t, m.answer(rawQuery(name, dnsmessage.TypeA)))
		if msg.Header.RCode != dnsmessage.RCodeFormatError || len(msg.Answers) != 0 {
			t.Errorf("%q: rcode %v with %d answers", name, msg.Header.RCode, len(msg.Answers))
		}
	}
	if _, ok := m.nameFor(netip.MustParseAddr("198.18.0.2")); ok {
		t.Fatal("a refused name was given an address")
	}
}

func TestUnderscoreAndDigitLabelsAreAccepted(t *testing.T) {
	m := newNameMap(nil, 0)
	for _, name := range []string{"_dmarc.example.org.", "1password.com.", "a-b.example.org.", "xn--bcher-kva.example."} {
		msg := parseAnswer(t, m.answer(buildQuery(t, name, dnsmessage.TypeA)))
		if msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Answers) != 1 {
			t.Errorf("%q: rcode %v with %d answers", name, msg.Header.RCode, len(msg.Answers))
		}
	}
}

func TestAFullMapGetsServFail(t *testing.T) {
	m := newNameMap(nil, 2)
	for _, name := range []string{"a.example.org.", "b.example.org."} {
		addressOf(t, parseAnswer(t, m.answer(buildQuery(t, name, dnsmessage.TypeA))))
	}
	msg := parseAnswer(t, m.answer(buildQuery(t, "c.example.org.", dnsmessage.TypeA)))
	if msg.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v", msg.Header.RCode)
	}
	// A name already in the map still answers.
	addressOf(t, parseAnswer(t, m.answer(buildQuery(t, "a.example.org.", dnsmessage.TypeA))))
}

func TestLocalNamesAnswerWithTheirOwnAddress(t *testing.T) {
	m := newNameMap(map[string]netip.Addr{"outerlayer-build": netip.MustParseAddr("127.0.0.1")}, 0)
	for _, name := range []string{"localhost.", "foo.localhost.", "outerlayer-build."} {
		got := addressOf(t, parseAnswer(t, m.answer(buildQuery(t, name, dnsmessage.TypeA))))
		if got != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestAnIPv4LiteralAnswersWithItself(t *testing.T) {
	m := newNameMap(nil, 0)
	got := addressOf(t, parseAnswer(t, m.answer(buildQuery(t, "1.1.1.1.", dnsmessage.TypeA))))
	if got != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("got %v", got)
	}
}

func TestAMessageThatIsNotAQueryIsNotAnswered(t *testing.T) {
	m := newNameMap(nil, 0)
	if got := m.answer([]byte{1, 2, 3}); got != nil {
		t.Fatalf("answered %v", got)
	}
	response := buildQuery(t, "a.example.org.", dnsmessage.TypeA)
	response[2] |= 0x80
	if got := m.answer(response); got != nil {
		t.Fatalf("answered a response")
	}
}

func TestTheFirstAndLastAddressesHandedOutLeaveTheReservedOnesFree(t *testing.T) {
	for _, limit := range []int{0, 1 << 20} {
		m := newNameMap(nil, limit)
		first, err := m.assign("first.example.org")
		if err != nil || first != netip.MustParseAddr("198.18.0.2") {
			t.Fatalf("limit %d: first address %v, %v", limit, first, err)
		}
		var last netip.Addr
		count := 1
		for {
			addr, err := m.assign("n" + strconv.Itoa(count) + ".example.org")
			if err != nil {
				break
			}
			last = addr
			count++
		}
		if last != netip.MustParseAddr("198.19.255.254") {
			t.Errorf("limit %d: last address %v", limit, last)
		}
		if want := 1<<17 - 3; count != want {
			t.Errorf("limit %d: %d names fit, want %d", limit, count, want)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Join([]string{label63, label63, label63, strings.Repeat("a", 61)}, ".")
	if len(name253) != 253 {
		t.Fatalf("test name has %d bytes", len(name253))
	}
	good := []string{"a", "0", "9a", "a-b", "_x", "Example.ORG.", label63 + ".org", name253}
	for _, name := range good {
		if _, err := normalizeName(name); err != nil {
			t.Errorf("%q refused: %v", name, err)
		}
	}
	bad := []string{"", ".", "a..b", ".a", label63 + "a.org", name253 + "a", "a b", "a:1", "a/b", "a\x00", "a`", "a{", "a@", "a[", "a/", "a:"}
	for _, name := range bad {
		if _, err := normalizeName(name); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestOnlyAnIPv4LiteralAnswersWithItself(t *testing.T) {
	m := newNameMap(nil, 0)
	addr, err := m.addressFor("::1")
	if err != nil || !syntheticRange.Contains(addr) {
		t.Fatalf("an IPv6 literal got %v, %v", addr, err)
	}
	if got, _ := m.addressFor("foolocalhost"); !syntheticRange.Contains(got) {
		t.Errorf("foolocalhost got %v", got)
	}
	if got, _ := m.addressFor("a.localhost"); got != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("a.localhost got %v", got)
	}
}

func TestAnswerFlagsAndRecord(t *testing.T) {
	m := newNameMap(nil, 0)
	msg := parseAnswer(t, m.answer(buildQuery(t, "api.example.org.", dnsmessage.TypeA)))
	if !msg.Header.Response || !msg.Header.RecursionAvailable || !msg.Header.RecursionDesired || msg.Header.ID != 7 {
		t.Errorf("header %+v", msg.Header)
	}
	if len(msg.Questions) != 1 || msg.Questions[0].Name.String() != "api.example.org." {
		t.Errorf("questions %+v", msg.Questions)
	}
	if got := msg.Answers[0].Header.TTL; got != answerTTL {
		t.Errorf("TTL %d", got)
	}
}

func TestAQueryThatIsNotAStandardQuestionGetsAnErrorCode(t *testing.T) {
	m := newNameMap(nil, 0)
	status := buildQuery(t, "a.example.org.", dnsmessage.TypeA)
	status[2] |= 2 << 3 // opcode STATUS
	if msg := parseAnswer(t, m.answer(status)); msg.Header.RCode != dnsmessage.RCodeNotImplemented {
		t.Errorf("opcode 2: rcode %v", msg.Header.RCode)
	}
	none := buildQuery(t, "a.example.org.", dnsmessage.TypeA)[:12]
	none[5] = 0 // no questions
	if msg := parseAnswer(t, m.answer(none)); msg.Header.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("no question: rcode %v", msg.Header.RCode)
	}
	two := dnsmessage.Message{Header: dnsmessage.Header{ID: 1}, Questions: []dnsmessage.Question{
		{Name: dnsmessage.MustNewName("a.example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		{Name: dnsmessage.MustNewName("b.example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
	}}
	raw, _ := two.Pack()
	if msg := parseAnswer(t, m.answer(raw)); msg.Header.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("two questions: rcode %v", msg.Header.RCode)
	}
	chaos := buildQuery(t, "a.example.org.", dnsmessage.TypeA)
	chaos[len(chaos)-1] = 3 // class CH
	if msg := parseAnswer(t, m.answer(chaos)); msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Answers) != 0 {
		t.Errorf("class CH: %+v", msg)
	}
}

func TestHostsFileNamesAndTheHostnameKeepTheirAddress(t *testing.T) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("no hostname")
	}
	p := filepath.Join(t.TempDir(), "hosts")
	text := "10.9.9.9 " + host + " alias.internal\n10.1.1.1 dup.internal\n10.2.2.2 dup.internal\n10.3.3.3\n# 10.4.4.4 hidden.internal\n10.5.5.5 shown.internal # c\n"
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadLocalNames(p)
	want := map[string]string{strings.ToLower(host): "10.9.9.9", "alias.internal": "10.9.9.9", "dup.internal": "10.1.1.1", "shown.internal": "10.5.5.5"}
	for name, addr := range want {
		if got[name] != netip.MustParseAddr(addr) {
			t.Errorf("%s: %v", name, got[name])
		}
	}
	if _, bad := got["hidden.internal"]; bad {
		t.Error("a commented line was read")
	}
	if got := loadLocalNames(filepath.Join(t.TempDir(), "missing")); len(got) > 1 {
		t.Errorf("a missing file gave %v", got)
	}
}

func TestTheUDPServerAnswersAQuery(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer pc.Close()
	go serveDNSUDP(pc, newNameMap(nil, 0))
	c, err := net.Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(buildQuery(t, "api.example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if addr := addressOf(t, parseAnswer(t, buf[:n])); !syntheticRange.Contains(addr) {
		t.Fatalf("answered %v", addr)
	}
}

func TestTheTCPServerAnswersFramedQueriesOnOneConnectionAndClosesOnNonsense(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer l.Close()
	go serveDNSTCP(l, newNameMap(nil, 0))
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	ask := func(msg []byte) []byte {
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
		if _, err := c.Write(append(frame, msg...)); err != nil {
			t.Fatal(err)
		}
		var length [2]byte
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return nil
		}
		out := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(c, out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := addressOf(t, parseAnswer(t, ask(buildQuery(t, "api.example.org.", dnsmessage.TypeA))))
	second := addressOf(t, parseAnswer(t, ask(buildQuery(t, "api.example.org.", dnsmessage.TypeA))))
	if first != second || !syntheticRange.Contains(first) {
		t.Fatalf("answers %v and %v", first, second)
	}
	if got := ask([]byte{1, 2, 3}); got != nil {
		t.Fatalf("answered nonsense with %v", got)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection stayed open after a message that is not a query")
	}
}
