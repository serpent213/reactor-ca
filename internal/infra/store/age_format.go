package store

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Age format validation functions based on the official age parser
// https://github.com/FiloSottile/age/blob/main/internal/format/format.go

type ageHeader struct {
	Recipients []*ageStanza
	MAC        []byte
}

type ageStanza struct {
	Type string
	Args []string
	Body []byte
}

var ageB64 = base64.RawStdEncoding.Strict()

func ageDecodeString(s string) ([]byte, error) {
	// CR and LF are ignored by DecodeString, but we don't want any malleability.
	if strings.ContainsAny(s, "\n\r") {
		return nil, errors.New(`unexpected newline character`)
	}
	return ageB64.DecodeString(s)
}

const (
	ageIntroLine      = "age-encryption.org/v1\n"
	ageColumnsPerLine = 64
	ageBytesPerLine   = ageColumnsPerLine / 4 * 3
)

var (
	ageStanzaPrefix = []byte("->")
	ageFooterPrefix = []byte("---")
)

type ageStanzaReader struct {
	r   *bufio.Reader
	err error
}

func newAgeStanzaReader(r *bufio.Reader) *ageStanzaReader {
	return &ageStanzaReader{r: r}
}

func (r *ageStanzaReader) readStanza() (s *ageStanza, err error) {
	// Read errors are unrecoverable.
	if r.err != nil {
		return nil, r.err
	}
	defer func() { r.err = err }()

	s = &ageStanza{}

	line, err := r.r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read line: %w", err)
	}
	if !bytes.HasPrefix(line, ageStanzaPrefix) {
		return nil, fmt.Errorf("malformed stanza opening line: %q", line)
	}
	prefix, args := ageSplitArgs(line)
	if prefix != string(ageStanzaPrefix) || len(args) < 1 {
		return nil, fmt.Errorf("malformed stanza: %q", line)
	}
	for _, a := range args {
		if !ageIsValidString(a) {
			return nil, fmt.Errorf("malformed stanza: %q", line)
		}
	}
	s.Type = args[0]
	s.Args = args[1:]

	for {
		line, err := r.r.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read line: %w", err)
		}

		b, err := ageDecodeString(strings.TrimSuffix(string(line), "\n"))
		if err != nil {
			if bytes.HasPrefix(line, ageFooterPrefix) || bytes.HasPrefix(line, ageStanzaPrefix) {
				return nil, fmt.Errorf("malformed body line %q: stanza ended without a short line", line)
			}
			return nil, fmt.Errorf("malformed body line %q: %v", line, err)
		}
		if len(b) > ageBytesPerLine {
			return nil, fmt.Errorf("malformed body line %q: too long", line)
		}
		s.Body = append(s.Body, b...)
		if len(b) < ageBytesPerLine {
			// A stanza body always ends with a short line.
			return s, nil
		}
	}
}

// validateAgeHeader parses an age file header to validate format correctness.
// Based on the official age Parse function.
func validateAgeHeader(input io.Reader) error {
	h := &ageHeader{}
	rr := bufio.NewReader(input)

	line, err := rr.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read intro: %w", err)
	}
	if line != ageIntroLine {
		return fmt.Errorf("unexpected intro: %q", line)
	}

	sr := newAgeStanzaReader(rr)
	for {
		peek, err := rr.Peek(len(ageFooterPrefix))
		if err != nil {
			return fmt.Errorf("failed to read header: %w", err)
		}

		if bytes.Equal(peek, ageFooterPrefix) {
			line, err := rr.ReadBytes('\n')
			if err != nil {
				return fmt.Errorf("failed to read header: %w", err)
			}

			prefix, args := ageSplitArgs(line)
			if prefix != string(ageFooterPrefix) || len(args) != 1 {
				return fmt.Errorf("malformed closing line: %q", line)
			}
			h.MAC, err = ageDecodeString(args[0])
			if err != nil || len(h.MAC) != 32 {
				return fmt.Errorf("malformed closing line %q: %v", line, err)
			}
			break
		}

		s, err := sr.readStanza()
		if err != nil {
			return fmt.Errorf("failed to parse header: %w", err)
		}
		h.Recipients = append(h.Recipients, s)
	}

	return nil
}

func ageSplitArgs(line []byte) (string, []string) {
	l := strings.TrimSuffix(string(line), "\n")
	parts := strings.Split(l, " ")
	return parts[0], parts[1:]
}

func ageIsValidString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
