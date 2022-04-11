package pkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/mitchellh/go-homedir"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"

	"github.com/anchore/grype/internal"
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
	reader, info, err := getSBOMReader(userInput, config)
	if err != nil {
		return nil, err
	}

	if info != nil {
		if (info.Scheme == "sbom" || info.ContentType == "sbom") && config.AttestationKey != "" {
			return nil, fmt.Errorf("key is meant for atttestation verification, your input is a plain SBOM and doesn't need it")
		}

		if info.Scheme == "att" && info.ContentType != "att" {
			return nil, fmt.Errorf("scheme specify an attestation but the content is not an attestation")
		}
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

func getSBOMReader(userInput string, config ProviderConfig) (io.Reader, *inputInfo, error) {
	switch {
	// the order of cases matter
	case userInput == "":
		// we only want to attempt reading in from stdin if the user has not specified other
		// options from the CLI, otherwise we should not assume there is any valid input from stdin.
		return decodeStdin(stdinReader(), config)

	case explicitlySpecifyingSBOM(userInput):
		filepath := strings.TrimPrefix(userInput, "sbom:")
		r, err := openFile(filepath)
		return r, newInputInfo("sbom", "sbom"), err

	case explicitlySpecifyAttestation(userInput):
		path := strings.TrimPrefix(userInput, "att:")
		f, err := openFile(path)
		if err != nil {
			return nil, nil, err
		}
		r, err := getSBOMFromAttestation(f, config)
		return r, newInputInfo("att", "att"), err

	case isPossibleAttestation(userInput):
		f, err := openFile(userInput)
		if err != nil {
			return nil, nil, err
		}
		r, err := getSBOMFromAttestation(f, config)
		return r, newInputInfo("", "att"), err

	case isPossibleSBOM(userInput):
		r, err := openFile(userInput)
		return r, newInputInfo("", "sbom"), err

	default:
		// no usable SBOM is available
		return nil, nil, errDoesNotProvide
	}
}

func decodeStdin(r io.Reader, config ProviderConfig) (io.Reader, *inputInfo, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading stdin: %w", err)
	}

	reader := bytes.NewReader(b)
	if hasInTotoPayload(b) {
		reader, err := getSBOMFromAttestation(reader, config)
		return reader, newInputInfo("", "att"), err
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
		return nil, fmt.Errorf("invalid payload type %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
	}

	if !config.IgnoreAttestationSignature {
		if config.AttestationKey == "" {
			return nil, fmt.Errorf("--key parameter is required to validate attestation")
		}

		if err := verifyAttestationSignature(env, config.AttestationKey); err != nil {
			return nil, fmt.Errorf("failed to verify attestation signature: %w", err)
		}
	}

	b, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation payload: %w", err)
	}

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
	pubKey, err := signature.PublicKeyFromKeyRef(context.TODO(), key)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	dssev, err := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: pubKey})
	if err != nil {
		return fmt.Errorf("failed to verify payload: %w", err)
	}

	acceptedKeys, err := dssev.Verify(env)
	if err != nil {
		return fmt.Errorf("failed to verify attestation: %w", err)
	}

	for i, s := range acceptedKeys {
		log.Infof("signature verified (%d/%d): key id %s, sig: %s", i+1, len(env.Signatures), s.KeyID, s.Sig)
	}

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

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return false
	}

	return hasInTotoPayload(b)
}

func isAncestorOfMimetype(mType *mimetype.MIME, expected string) bool {
	for cur := mType; cur != nil; cur = cur.Parent() {
		if cur.Is(expected) {
			return true
		}
	}
	return false
}

func hasInTotoPayload(b []byte) bool {
	return bytes.Contains(b, []byte(types.IntotoPayloadType))
}

func explicitlySpecifyingSBOM(userInput string) bool {
	return strings.HasPrefix(userInput, "sbom:")
}

func explicitlySpecifyAttestation(userInput string) bool {
	return strings.HasPrefix(userInput, "att:")
}
