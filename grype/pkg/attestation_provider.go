package pkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func syftAttestationProvider(userInput string, config ProviderConfig) ([]Package, Context, error) {
	if explicitlySpecifyAttestation(userInput) {
		filepath := strings.TrimPrefix(userInput, "att:")
		log.Debugf("attestation file path: %s", filepath)
		log.Debugf("attestation public key path: %s", config.PublicKey)

		f, err := os.Open(filepath)
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to open attestation file %s: %w", filepath, err)
		}
		defer func() {
			err := f.Close()
			if err != nil {
				log.Warnf("failed to close public key file: %v", err)
			}
		}()

		env := &ssldsse.Envelope{}
		err = json.NewDecoder(f).Decode(env)
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to decode attestation envelope: %w", err)
		}

		if env.PayloadType != types.IntotoPayloadType {
			return nil, Context{}, fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
		}

		pubKey, err := signature.PublicKeyFromKeyRef(context.TODO(), config.PublicKey)
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to load public key: %w", err)
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}

		dssev, err := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: pubKey})
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to verify payload: %w", err)
		}

		_, err = dssev.Verify(env)
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to verify attestation: %w", err)
		}

		b, _ := base64.StdEncoding.DecodeString(env.Payload)
		//fmt.Printf("payload: %s\nerr: %v", b, err)

		stmt := &in_toto.Statement{}
		err = json.Unmarshal(b, stmt)
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to extract in-toto statement: %w", err)
		}

		pb, err := json.Marshal(stmt.Predicate)
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to process predicate: %w", err)
		}

		sbom, format, err := syft.Decode(bytes.NewBuffer(pb))
		if err != nil {
			return nil, Context{}, fmt.Errorf("failed to decode predicate: %w", err)
		}
		log.Debugf("extracted SBOM from statement with format: %s", format)

		return FromCatalog(sbom.Artifacts.PackageCatalog, config), Context{
			Source: &sbom.Source,
			Distro: sbom.Artifacts.LinuxDistribution,
		}, nil
	}

	return nil, Context{}, errDoesNotProvide
}
