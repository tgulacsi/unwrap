package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
)

// See http://marcel.vandewaters.nl/oracle/security/unwrapping-wrapped-plsql-in-10g-and-11g

//go:generate sh -c "go run ./testdata/ascii.go >testdata/ascii.sql"
//go:generate sh -c "ulimit -d unlimited; wrap edebug=wrap_new_sql iname=testdata/ascii oname=testdata/ascii"
//go:generate sh -c "go run ./unwrap.go -no-decode <testdata/ascii.plb >testdata/ascii.uw"
//go:generate sh -c "go run ./testdata/mktable.go <testdata/ascii.uw >tbl.go"

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
	}
}

func Main() error {
	flagVerbose := flag.Bool("v", false, "verbose logging")
	flagNoDecode := flag.Bool("no-decode", false, "no decode (for table building)")
	flag.Parse()
	logger := log.NewNopLogger()
	if *flagVerbose {
		logger = log.NewLogfmtLogger(os.Stderr)
	}
	U := NewUnwraper(os.Stdin, WithLogger(logger), WithNoDecode(*flagNoDecode))
	for {
		_, err := U.Unwrap(os.Stdout)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}

type Type byte

const (
	TypProcedure   = Type('7')
	TypFunction    = Type('8')
	TypPackage     = Type('9')
	TypPackageBody = Type('b')
	TypType        = Type('d')
	TypTypeBody    = Type('e')
)

// Unwrap a PL/SQL wrapped procedure,
// from
// http://marcel.vandewaters.nl/oracle/security/unwrapping-wrapped-plsql-in-10g-and-11g
func NewUnwraper(r io.Reader, options ...option) unwrapper {
	U := unwrapper{r: bufio.NewReader(r)}
	for _, o := range options {
		o(&U)
	}
	return U
}

func WithLogger(logger log.Logger) option {
	return func(U *unwrapper) {
		U.Logger = logger
	}
}
func WithNoDecode(nodecode bool) option {
	return func(U *unwrapper) {
		U.noDecode = nodecode
	}
}

var charMap [256]byte

type option func(*unwrapper)

type unwrapper struct {
	r *bufio.Reader
	log.Logger
	noDecode bool
}

func (U unwrapper) Unwrap(w io.Writer) (Type, error) {
	var typ Type
	var lineno int
	var wrappedLength int64
	var started bool
	for {
		line, err := U.r.ReadBytes('\n')
		lineno++
		if err != nil {
			if err == io.EOF {
				return typ, io.EOF
			}
			return typ, errors.Wrapf(err, "read %d. line", lineno)
		}
		if U.Log != nil {
			U.Log("lineno", lineno, "line", string(line))
		}
		if i := len(line) - 1; line[i] == '\n' {
			line = line[:i]
		}
		if !started {
			if started = bytes.HasSuffix(bytes.TrimSpace(line), []byte(" wrapped")); started {
				lineno = 1
			}
			continue
		}

		if lineno < 19 {
			continue
		}
		if lineno == 19 {
			// Line 19:
			// A hex value specifying the type of PL/SQL object (all type of PL/SQL objects that can be wrapped)
			typ = Type(bytes.TrimSpace(line)[0])
			continue
		}
		if lineno == 20 {
			// Line 20:
			// The last line of the header contains two hex values separated by a space.
			// These values contain length information.
			// The first value contains the length of the unwrapped text (without the CREATE OR REPLACE part).
			// The second value contains the length of the wrapped body without the header and without the ending LF (0x0A) and “/” sign.
			parts := bytes.SplitN(line, []byte{' '}, 2)
			//uwl, err := strconv.ParseInt(string(parts[0]), 16, 32)
			wrappedLength, err = strconv.ParseInt(string(parts[1]), 16, 32)
			if U.Log != nil {
				U.Log("wrappedLength", wrappedLength)
			}
		}
		break
	}
	if !(started && lineno == 20) {
		return typ, io.EOF
	}

	b64r := base64.NewDecoder(base64.StdEncoding, &io.LimitedReader{R: U.r, N: int64(wrappedLength)})
	// The first 20 bytes of the BASE64 decoded body contains a SHA1 hash value for the wrapped (encrypted) body.
	var hsh [20]byte
	if _, err := io.ReadFull(b64r, hsh[:]); err != nil {
		return typ, errors.Wrap(err, "read hash")
	}

	// As mentioned before, the wrapped PL/SQL text is BASE64 coded and needs to be decoded before you can actually start unwrapping (decrypting).
	// The remaining of the body is a coded (using a codetable) compressed stream of bytes that contains the source text.

	var err error
	if U.noDecode {
		_, err = io.Copy(w, b64r)
		return typ, err
	}

	b := make([]byte, 4096)
	for {
		var n int
		n, err = b64r.Read(b[:])
		b = b[:n]
		for i, c := range b {
			b[i] = charMap[c]
		}
		if _, wErr := w.Write(b); wErr != nil && err == nil {
			return typ, wErr
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
	}

	return typ, err
}
