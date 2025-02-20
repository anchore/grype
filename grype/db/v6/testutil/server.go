package dbtest

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/zstd"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v5/namespace"
	distroNs "github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/schemaver"
)

type ServerBuilder struct {
	t               *testing.T
	dbContents      []byte
	DBFormat        string
	DBName          string
	DBBuildTime     time.Time
	Vulnerabilities []vulnerability.Vulnerability
	LatestDoc       *distribution.LatestDocument
	LatestDocPath   string
	RequestHandler  http.HandlerFunc
}

func (s *ServerBuilder) SetDBBuilt(t time.Time) *ServerBuilder {
	s.DBBuildTime = t
	return s
}

func (s *ServerBuilder) WithHandler(handler http.HandlerFunc) *ServerBuilder {
	s.RequestHandler = handler
	return s
}

// NewServer creates a new test db server building a single database from the provided
// vulnerabilities, along with a latest.json pointing to it, optionally with any properties
// specified in the provided latest parameter
func NewServer(t *testing.T) *ServerBuilder {
	t.Helper()
	now := time.Now()
	return &ServerBuilder{
		t: t,

		DBFormat:    "tar.zst",
		DBName:      "vulnerability-db_v6.0.0",
		DBBuildTime: time.Now().Add(-1 * 24 * time.Hour), // 1 day ago

		LatestDocPath:   "latest.json",
		Vulnerabilities: DefaultVulnerabilities(),
		LatestDoc: &distribution.LatestDocument{
			Status: "active",
			Archive: distribution.Archive{
				Description: v6.Description{
					SchemaVersion: schemaver.New(6, 0, 0),
					Built:         v6.Time{Time: now},
				},
			},
		},
	}
}

// Start starts builds a database and starts a server with the current settings
// if you need to rebuild a DB or modify the behavior, you can either set
// a custom RequestHandler func or modify the settings and call Start() again.
// Returns a URL to the latest.json file, e.g. http://127.0.0.1:5678/latest.json
func (s *ServerBuilder) Start() (url string) {
	s.t.Helper()

	contents := s.buildDB()
	s.dbContents = pack(s.t, s.DBFormat, contents)

	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if s.RequestHandler != nil {
			rw := wrappedWriter{writer: w}
			s.RequestHandler(&rw, r)
			if rw.handled {
				return
			}
		}

		archivePath := s.DBName + "." + s.DBFormat
		switch r.RequestURI[1:] {
		case s.LatestDocPath:
			latestDoc := *s.LatestDoc
			latestDoc.Built.Time = s.DBBuildTime
			latestDoc.Archive.Built.Time = s.DBBuildTime
			latestDoc.Archive.Path = archivePath
			latestDoc.Archive.Checksum = sha(s.dbContents)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(latestDoc)
		case archivePath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(s.dbContents)
		default:
			http.NotFound(w, r)
			return
		}
	})
	mockSrv := httptest.NewServer(handler)
	s.t.Cleanup(func() {
		mockSrv.Close()
	})
	return mockSrv.URL + "/" + s.LatestDocPath
}

func sha(contents []byte) string {
	digest, err := file.HashReader(bytes.NewReader(contents), sha256.New())
	if err != nil {
		panic(err)
	}
	return "sha256:" + digest
}

//nolint:funlen
func (s *ServerBuilder) buildDB() []byte {
	s.t.Helper()

	tmp := s.t.TempDir()
	w, err := v6.NewWriter(v6.Config{
		DBDirPath: tmp,
	})
	require.NoError(s.t, err)

	aWeekAgo := time.Now().Add(-7 * 24 * time.Hour)
	twoWeeksAgo := time.Now().Add(-14 * 24 * time.Hour)

	for _, v := range s.Vulnerabilities {
		prov := &v6.Provider{
			ID:           "nvd",
			Version:      "1",
			DateCaptured: &s.DBBuildTime,
		}

		var operatingSystem *v6.OperatingSystem
		packageType := ""

		ns, err := namespace.FromString(v.Namespace)
		require.NoError(s.t, err)

		d, _ := ns.(*distroNs.Namespace)
		if d != nil {
			packageType = string(d.DistroType())
			operatingSystem = &v6.OperatingSystem{
				Name:         d.Provider(),
				MajorVersion: strings.Split(d.Version(), ".")[0],
			}
			prov.ID = d.Provider()
		}
		lang, _ := ns.(*language.Namespace)
		if lang != nil {
			packageType = string(lang.Language())
		}

		prov.Processor = prov.ID + "-processor"
		prov.InputDigest = sha([]byte(prov.ID))

		vuln := &v6.VulnerabilityHandle{
			ID:            0,
			Name:          v.ID,
			Status:        "",
			PublishedDate: &twoWeeksAgo,
			ModifiedDate:  &aWeekAgo,
			WithdrawnDate: nil,
			ProviderID:    prov.ID,
			Provider:      prov,
			BlobID:        0,
			BlobValue: &v6.VulnerabilityBlob{
				ID:          v.ID,
				Assigners:   []string{v.ID + "-assigner-1", v.ID + "-assigner-2"},
				Description: v.ID + "-description",
				References: []v6.Reference{
					{
						URL:  "http://somewhere/" + v.ID,
						Tags: []string{v.ID + "-tag-1", v.ID + "-tag-2"},
					},
				},
				//Aliases: []string{"GHSA-" + v.ID},
				Severities: []v6.Severity{
					{
						Scheme: v6.SeveritySchemeCVSS,
						Value:  "high",
						Source: "",
						Rank:   0,
					},
				},
			},
		}

		err = w.AddVulnerabilities(vuln)
		require.NoError(s.t, err)

		var cpes []v6.Cpe
		for _, cp := range v.CPEs {
			require.NoError(s.t, err)
			cpes = append(cpes, v6.Cpe{
				Part:            cp.Attributes.Part,
				Vendor:          cp.Attributes.Vendor,
				Product:         cp.Attributes.Product,
				Edition:         cp.Attributes.Edition,
				Language:        cp.Attributes.Language,
				SoftwareEdition: cp.Attributes.SWEdition,
				TargetHardware:  cp.Attributes.TargetHW,
				TargetSoftware:  cp.Attributes.TargetSW,
				Other:           cp.Attributes.Other,
			})
		}

		pkg := &v6.Package{
			ID:        0,
			Ecosystem: packageType,
			Name:      v.PackageName,
		}

		if prov.ID != "nvd" {
			pkg.CPEs = cpes
		} else {
			for _, c := range cpes {
				ac := &v6.AffectedCPEHandle{
					Vulnerability: vuln,
					CPE:           &c,
					BlobValue: &v6.AffectedPackageBlob{
						Ranges: []v6.AffectedRange{
							{
								Version: toAffectedVersion(v.Constraint),
							},
						},
					},
				}

				err = w.AddAffectedCPEs(ac)
				require.NoError(s.t, err)
			}
		}

		ap := &v6.AffectedPackageHandle{
			ID:                0,
			VulnerabilityID:   0,
			Vulnerability:     vuln,
			OperatingSystemID: nil,
			OperatingSystem:   operatingSystem,
			PackageID:         0,
			Package:           pkg,
			BlobID:            0,
			BlobValue: &v6.AffectedPackageBlob{
				CVEs:       nil,
				Qualifiers: nil,
				Ranges: []v6.AffectedRange{
					{
						Fix:     nil,
						Version: toAffectedVersion(v.Constraint),
					},
				},
			},
		}

		err = w.AddAffectedPackages(ap)
		require.NoError(s.t, err)
	}

	err = w.SetDBMetadata()
	require.NoError(s.t, err)

	err = w.Close()
	require.NoError(s.t, err)

	contents, err := os.ReadFile(filepath.Join(tmp, "vulnerability.db"))
	require.NoError(s.t, err)

	return contents
}

func pack(t *testing.T, typ string, contents []byte) []byte {
	if typ == "tar.zst" {
		now := time.Now()
		tarContents := bytes.Buffer{}
		tw := tar.NewWriter(&tarContents)
		err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     "vulnerability.db",
			Size:     int64(len(contents)),
			Mode:     0777,
			ModTime:  now,
		})
		require.NoError(t, err)
		_, err = tw.Write(contents)
		require.NoError(t, err)
		err = tw.Close()
		require.NoError(t, err)

		var tarZstd []byte
		tarZstd, err = zstd.Compress(tarZstd, tarContents.Bytes())
		require.NoError(t, err)

		return tarZstd
	}

	panic("unsupported type: " + typ)
}

func toAffectedVersion(c version.Constraint) v6.AffectedVersion {
	parts := strings.SplitN(c.String(), "(", 2)
	if len(parts) < 2 {
		return v6.AffectedVersion{
			Constraint: strings.TrimSpace(parts[0]),
		}
	}
	return v6.AffectedVersion{
		Type:       strings.TrimSpace(strings.Split(parts[1], ")")[0]),
		Constraint: strings.TrimSpace(parts[0]),
	}
}

type wrappedWriter struct {
	writer  http.ResponseWriter
	handled bool
}

func (w *wrappedWriter) Header() http.Header {
	w.handled = true
	return w.writer.Header()
}

func (w *wrappedWriter) Write(contents []byte) (int, error) {
	w.handled = true
	return w.writer.Write(contents)
}

func (w *wrappedWriter) WriteHeader(statusCode int) {
	w.handled = true
	w.writer.WriteHeader(statusCode)
}
