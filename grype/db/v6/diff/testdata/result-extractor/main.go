package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/grype/grype/db/v6/testdb"
)

var (
	outputPath string
	vuln       string
)

func main() {
	var err error

	flag.StringVar(&outputPath, "output-path", "testdata", "path to output directory")
	flag.StringVar(&vuln, "vuln", "", "path to output directory")
	flag.Parse()

	args := flag.Args()

	if len(args) != 1 {
		flag.Usage()
		log.Fatal("usage: required arg <path to vunnel results directory>")
	}

	var basePath = args[0]

	if !filepath.IsAbs(outputPath) {
		_, filename, _, ok := runtime.Caller(0)
		if !ok {
			log.Fatal("Could not get caller information")
		}

		fmt.Printf("Full file path: %s\n", filename)

		// To get just the directory containing the file:
		outputPath = filepath.Join(filepath.Dir(filename), outputPath)
		outputPath = filepath.Clean(outputPath)
	}

	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		log.Fatalf("failed to get absolute path: %v", err)
	}

	pattern := "**/results/results.db"

	fsys := os.DirFS(basePath)
	matches, err := doublestar.Glob(fsys, pattern)
	if err != nil {
		log.Fatalf("failed to glob: %v", err)
	}

	if len(matches) == 0 {
		log.Println("no matching databases found")
		return
	}

	search := "cast(record as text) LIKE '%fix%' AND _ROWID_ >= (abs(random()) % (SELECT max(_ROWID_) FROM results)) LIMIT 1"
	if vuln != "" {
		search = "lower(id) LIKE lower('%" + vuln + "')"
	}

	type rec struct {
		provider string
		id       string
		json     map[string]any
	}

	// results keyed by provider
	var results []rec

	for _, match := range matches {
		dbPath := filepath.Join(basePath, match)
		log.Printf("opening %s", dbPath)

		func() {
			db, err := sql.Open("sqlite", dbPath+"?mode=ro")
			if err != nil {
				log.Printf("failed to open %s: %v", dbPath, err)
				return
			}

			query := `SELECT id, record FROM results WHERE ` + search
			log.Printf("querying %s", query)

			var id, record string

			defer db.Close()

			rows, err := db.Query(query)
			if err != nil {
				if err == sql.ErrNoRows {
					log.Printf("no matching rows in %s", dbPath)
				} else {
					log.Printf("query failed for %s: %v", dbPath, err)
				}
				return
			}

			for rows.Next() {
				rows.Scan(&id, &record)

				provider := strings.TrimPrefix(match, basePath)
				provider = strings.Split(strings.Trim(filepath.ToSlash(provider), "/"), "/")[0]

				contents := map[string]any{}

				err = json.Unmarshal([]byte(record), &contents)
				if err != nil {
					log.Printf("failed to unmarshal JSON for %s: %v", dbPath, err)
					continue
				}

				results = append(results, rec{
					provider: provider,
					id:       id,
					json:     contents,
				})
			}
		}()
	}

	// Write each result to a JSON file named after name1
	for _, r := range results {
		data, err := json.MarshalIndent(r.json, "", "  ")
		if err != nil {
			log.Printf("failed to marshal JSON for %s / %s: %v", r.provider, r.id, err)
			continue
		}

		filename := filepath.Join(outputPath, r.provider, "results", fmt.Sprintf("%s.json", testdb.CleanPath(r.id)))
		err = os.MkdirAll(filepath.Dir(filename), 0o755)
		if err != nil {
			log.Printf("failed to create directory %s: %v", filepath.Dir(filename), err)
			continue
		}
		err = os.WriteFile(filename, data, 0o644)
		if err != nil {
			log.Printf("failed to write %s: %v", filename, err)
			continue
		}

		log.Printf("wrote %s", filename)
	}
}
