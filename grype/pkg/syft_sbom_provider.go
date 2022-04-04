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
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
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

func getSBOM(userInput string, config ProviderConfig) (*sbom.SBOM, error) {
	reader, err := getSBOMReader(userInput, config)
	if err != nil {
		return nil, err
	}

	s, format, err := syft.Decode(reader)
	if err != nil && err.Error() == "unable to identify format" && !explicitlySpecifyAttestation(userInput) {
		return getSBOM(fmt.Sprintf("att:%s", userInput), config)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to decode sbom: %w", err)
	}

	if format == nil {
		return nil, errDoesNotProvide
	}

	return s, nil
}

func getSBOMReader(userInput string, config ProviderConfig) (io.Reader, error) {
	switch {
	// order of cases matter
	case userInput == "":
		// we only want to attempt reading in from stdin if the user has not specified other
		// options from the CLI, otherwise we should not assume there is any valid input from stdin.
		return stdinReader(), nil

	case explicitlySpecifyingSBOM(userInput):
		filepath := strings.TrimPrefix(userInput, "sbom:")
		sbomFile, err := openSbom(filepath)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified SBOM: %w", err)
		}

		return sbomFile, nil
	case isPossibleSBOM(userInput):
		sbomFile, err := openSbom(userInput)
		if err == nil {
			return sbomFile, nil
		}
		log.Warnf("failed openning input file: %v", err)
	case explicitlySpecifyAttestation(userInput):
		filepath := strings.TrimPrefix(userInput, "att:")
		return getSbomFromAttestation(filepath, config)
	}

	// no usable SBOM is available
	return nil, errDoesNotProvide
}

// fileHasContent returns a bool indicating whether the given SBOM file has data that could possibly be utilized in
// downstream processing.
func fileHasContent(sbom *os.File) bool {
	if sbom == nil {
		return false
	}

	info, err := sbom.Stat()
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
	err := f.Close()
	if err != nil {
		log.Warnf("failed to close public key file: %v", err)
	}
}

func getSbomFromAttestation(file string, config ProviderConfig) (io.Reader, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open attestation file %s: %w", file, err)
	}
	defer closeFile(f)

	if !fileHasContent(f) {
		return nil, errEmptySBOM{file}
	}

	env := &ssldsse.Envelope{}
	err = json.NewDecoder(f).Decode(env)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation envelope: %w", err)
	}

	if env.PayloadType != types.IntotoPayloadType {
		return nil, fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
	}

	if err := verifyAttestationSignature(env, config.Key); err != nil {
		return nil, fmt.Errorf("failed to verify attestation signature: %w", err)
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
		return nil, fmt.Errorf("failed to process predicate: %w", err)
	}

	return bytes.NewBuffer(pb), nil
}

func verifyAttestationSignature(env *ssldsse.Envelope, key string) error {
	pubKey, err := signature.PublicKeyFromKeyRef(context.TODO(), key)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}
	pkcs11Key, ok := pubKey.(*pkcs11key.Key)
	if ok {
		defer pkcs11Key.Close()
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

func openSbom(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	sbomFile, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	if !fileHasContent(sbomFile) {
		return nil, errEmptySBOM{path}
	}

	return sbomFile, nil
}

func isPossibleSBOM(userInput string) bool {
	f, err := os.Open(userInput)
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
