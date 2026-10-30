package csaf

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

// loadAdvisory loads a CSAF VEX document, working around the gocsaf v3 loader's
// mistyped product group fields (gocsaf/csaf#783): CSAF 2.0 defines
// product_tree/product_groups and the group_id lists of a vulnerability as
// arrays, which gocsaf v3 cannot parse at all. When a document fails to load,
// every group reference is resolved to its member product IDs -- per CSAF 2.0
// sections 3.1.6 and 3.2.2.3 a group reference denotes all of its members --
// and the load is retried. Spec-conformant documents are then handled the same
// way as documents that name the products directly, instead of silently
// falling through to the OpenVEX processor (which keys statements by CSAF
// product ID and therefore never matches a package).
func loadAdvisory(path string) (*gocsaf.Advisory, error) {
	adv, err := gocsaf.LoadAdvisory(path)
	if err == nil {
		return adv, nil
	}

	resolved, changed, resolveErr := resolveProductGroups(path)
	if resolveErr != nil {
		// the document is unreadable in a way the workaround cannot help with
		return nil, err
	}
	if !changed {
		return nil, err
	}

	tmp, err := os.CreateTemp("", "grype-csaf-*.json")
	if err != nil {
		return nil, fmt.Errorf("unable to stage group-resolved CSAF document: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(resolved); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("unable to stage group-resolved CSAF document: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("unable to stage group-resolved CSAF document: %w", err)
	}

	return gocsaf.LoadAdvisory(tmp.Name())
}

// resolveProductGroups rewrites a CSAF document so that no product group
// fields remain: the group definitions under product_tree/product_groups are
// collected and removed, and any group_ids reference in the flags, threats,
// or remediations of a vulnerability is replaced by the member product IDs of
// the referenced groups (merged into product_ids). It returns the rewritten
// document and whether any change was needed.
func resolveProductGroups(path string) ([]byte, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, err
	}

	groupMembers := map[string][]string{}
	changed := false

	if tree, ok := doc["product_tree"].(map[string]any); ok {
		if groups, ok := tree["product_groups"].([]any); ok {
			for _, group := range groups {
				member, ok := group.(map[string]any)
				if !ok {
					continue
				}
				groupID, _ := member["group_id"].(string)
				if groupID == "" {
					continue
				}
				groupMembers[groupID] = stringSlice(member["product_ids"])
			}
			// the loader cannot parse the group definitions themselves
			delete(tree, "product_groups")
			changed = true
		}
	}

	vulnerabilities, _ := doc["vulnerabilities"].([]any)
	for _, vulnerability := range vulnerabilities {
		vuln, ok := vulnerability.(map[string]any)
		if !ok {
			continue
		}
		for _, section := range []string{"flags", "threats", "remediations"} {
			entries, _ := vuln[section].([]any)
			for _, entry := range entries {
				item, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				groupIDs, ok := item["group_ids"].([]any)
				if !ok {
					continue
				}
				productIDs := stringSlice(item["product_ids"])
				for _, groupID := range stringSlice(groupIDs) {
					productIDs = mergeUnique(productIDs, groupMembers[groupID])
				}
				if len(productIDs) > 0 {
					item["product_ids"] = productIDs
				}
				delete(item, "group_ids")
				changed = true
			}
		}
	}

	if !changed {
		return nil, false, nil
	}

	resolved, err := json.Marshal(doc)
	if err != nil {
		return nil, false, err
	}

	return resolved, true, nil
}

// LooksLikeCSAF reports whether the document declares itself as a CSAF
// document, based on the required document/csaf_version field or the CSAF
// JSON schema, even when the document cannot be fully loaded.
func LooksLikeCSAF(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var doc struct {
		Schema   string `json:"$schema"`
		Document struct {
			CSAFVersion string `json:"csaf_version"`
		} `json:"document"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false
	}

	return doc.Document.CSAFVersion != "" || strings.Contains(strings.ToLower(doc.Schema), "csaf")
}

// stringSlice converts a JSON array to a slice of its string elements,
// skipping non-string entries.
func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}

	var out []string
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

// mergeUnique appends the values of added to existing, skipping duplicates.
func mergeUnique(existing, added []string) []string {
	merged := slices.Clone(existing)
	for _, s := range added {
		if !slices.Contains(merged, s) {
			merged = append(merged, s)
		}
	}
	return merged
}
