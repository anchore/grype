package pkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/mitchellh/go-homedir"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
)

type errEmptySBOM struct {
	sbomFilepath string
}

func (e errEmptySBOM) Error() string {
	return fmt.Sprintf("SBOM file is empty: %s", e.sbomFilepath)
}

func syftSBOMProvider(userInput string, config ProviderConfig) ([]Package, Context, error) {
	s, err := getSBOM(userInput, config)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(s.Artifacts.PackageCatalog, config), Context{
		Source: &s.Source,
		Distro: s.Artifacts.LinuxDistribution,
	}, nil
}

func newInputInfo(scheme, contentTye string) *inputInfo {
	return &inputInfo{
		Scheme:      scheme,
		ContentType: contentTye,
	}
}

type inputInfo struct {
	ContentType string
	Scheme      string
}

func getSBOM(userInput string, config ProviderConfig) (*sbom.SBOM, error) {
	reader, err := getSBOMReader(userInput, config)
	if err != nil {
		return nil, err
	}

	s, format, err := syft.Decode(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode sbom: %w", err)
	}

	if format == nil {
		return nil, errDoesNotProvide
	}

	return s, nil
}

func getSBOMReader(userInput string, config ProviderConfig) (r io.Reader, err error) {
	r, info, err := extractReaderAndInfo(userInput, config)
	if err != nil {
		return nil, err
	}

	if info != nil {
		if (info.Scheme == "sbom" || info.ContentType == "sbom") && config.AttestationPublicKey != "" {
			return nil, fmt.Errorf("key is meant for attestation verification, your input is a plain SBOM and doesn't need it")
		}

		if info.Scheme == "att" && info.ContentType != "att" {
			return nil, fmt.Errorf("scheme specify an attestation but the content is not an attestation")
		}
	}

	return r, nil
}

func extractReaderAndInfo(userInput string, config ProviderConfig) (io.Reader, *inputInfo, error) {
	switch {
	// the order of cases matter
	case userInput == "":
		// we only want to attempt reading in from stdin if the user has not specified other
		// options from the CLI, otherwise we should not assume there is any valid input from stdin.
		return decodeStdin(stdinReader(), config)

	case explicitlySpecifyingSBOM(userInput):
		filepath := strings.TrimPrefix(userInput, "sbom:")
		return parseSBOM("sbom", filepath)

	case explicitlySpecifyAttestation(userInput):
		path := strings.TrimPrefix(userInput, "att:")
		return parseAttestation("att", path, config)

	case isPossibleAttestation(userInput):
		return parseAttestation("", userInput, config)

	case isPossibleSBOM(userInput):
		return parseSBOM("", userInput)

	default:
		return nil, nil, errDoesNotProvide
	}
}

func parseSBOM(scheme, path string) (io.Reader, *inputInfo, error) {
	r, err := openFile(path)
	if err != nil {
		return nil, nil, err
	}
	info := newInputInfo(scheme, "sbom")
	return r, info, nil
}

func parseAttestation(scheme, path string, config ProviderConfig) (io.Reader, *inputInfo, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, nil, err
	}
	r, err := getSBOMFromAttestation(f, config)
	if err != nil {
		return nil, nil, err
	}
	info := newInputInfo(scheme, "att")
	return r, info, nil
}

func decodeStdin(r io.Reader, config ProviderConfig) (io.Reader, *inputInfo, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading stdin: %w", err)
	}

	reader := bytes.NewReader(b)
	if isDSSEEnvelope(reader) {
		_, err := reader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse stdin: %w", err)
		}

		reader, err := getSBOMFromAttestation(reader, config)
		return reader, newInputInfo("", "att"), err
	}

	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse stdin: %w", err)
	}

	return reader, newInputInfo("", "sbom"), nil
}

// fileHasContent returns a bool indicating whether the given file has data that could possibly be utilized in
// downstream processing.
func fileHasContent(f *os.File) bool {
	if f == nil {
		return false
	}

	info, err := f.Stat()
	if err != nil {
		return false
	}

	if size := info.Size(); size > 0 {
		return true
	}

	return false
}

func stdinReader() io.Reader {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return nil
	}

	if !isPipedInput {
		return nil
	}

	return os.Stdin
}

func closeFile(f *os.File) {
	if f == nil {
		return
	}

	err := f.Close()
	if err != nil {
		log.Warnf("failed to close file %s: %v", f.Name(), err)
	}
}

func getSBOMFromAttestation(r io.Reader, config ProviderConfig) (io.Reader, error) {
	env := &ssldsse.Envelope{}
	err := json.NewDecoder(r).Decode(env)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation envelope: %w", err)
	}

	if env.PayloadType != types.IntotoPayloadType {
		return nil, fmt.Errorf("invalid attestation payload")
	}

	if !config.AttestationIgnoreVerification {
		if config.AttestationPublicKey == "" {
			return nil, fmt.Errorf("--key parameter is required to validate attestations")
		}

		if err := verifyAttestationSignature(env, config.AttestationPublicKey); err != nil {
			return nil, fmt.Errorf("failed to verify attestation signature: %w", err)
		}
	} else {
		bus.Publish(partybus.Event{
			Type: event.AttestationVerificationSkipped,
		})
	}

	b, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation payload: %w", err)
	}

	// a statement contains predicate and subject, the digest present in the subject
	// comes from RepoDigests -- according to Syft's implementation
	stmt := &in_toto.Statement{}
	err = json.Unmarshal(b, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to extract in-toto statement: %w", err)
	}

	pb, err := json.Marshal(stmt.Predicate)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(pb), nil
}

func verifyAttestationSignature(env *ssldsse.Envelope, key string) error {
	pubKey, err := signature.PublicKeyFromKeyRef(context.Background(), key)
	if err != nil {
		log.Warnf("failed to get public get from key reference: %v", err)
		return fmt.Errorf("cannot decode public key")
	}

	dssev, err := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: pubKey})
	if err != nil {
		return fmt.Errorf("failed to verify payload: %w", err)
	}

	acceptedKeys, err := dssev.Verify(env)
	if err != nil {
		log.Warnf("key and signature don't match: %v", err)
		return fmt.Errorf("key and signature don't match")
	}

	for i, s := range acceptedKeys {
		log.Infof("verified signature (%d/%d): key id %s, sig: %s", i+1, len(env.Signatures), s.KeyID, s.Sig)
	}

	bus.Publish(partybus.Event{
		Type: event.AttestationVerified,
	})

	return nil
}

func openFile(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	f, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", expandedPath, err)
	}

	if !fileHasContent(f) {
		return nil, errEmptySBOM{path}
	}

	return f, nil
}

func isPossibleSBOM(userInput string) bool {
	f, err := openFile(userInput)
	if err != nil {
		return false
	}
	defer closeFile(f)

	mType, err := mimetype.DetectReader(f)
	if err != nil {
		return false
	}

	// we expect application/json, application/xml, and text/plain input documents. All of these are either
	// text/plain or a descendant of text/plain. Anything else cannot be an input SBOM document.
	return isAncestorOfMimetype(mType, "text/plain")
}

func isPossibleAttestation(userInput string) bool {
	f, err := openFile(userInput)
	if err != nil {
		return false
	}
	defer closeFile(f)

	return isDSSEEnvelope(f)
}

// isDSSEEnvelope validates r contains a DSSE envelope, which is the best
// indicator for an attestations created by Syft
func isDSSEEnvelope(r io.Reader) bool {
	env := &ssldsse.Envelope{}
	err := json.NewDecoder(r).Decode(env)
	if err != nil {
		return false
	}

	return env.PayloadType == types.IntotoPayloadType
}

func isAncestorOfMimetype(mType *mimetype.MIME, expected string) bool {
	for cur := mType; cur != nil; cur = cur.Parent() {
		if cur.Is(expected) {
			return true
		}
	}
	return false
}

func explicitlySpecifyingSBOM(userInput string) bool {
	return strings.HasPrefix(userInput, "sbom:")
}

func explicitlySpecifyAttestation(userInput string) bool {
	return strings.HasPrefix(userInput, "att:")
}
