package version

//func TestFuzzyVersionCompare(t *testing.T) {
//	tests := []struct {
//		name           string
//		thisVersion    string
//		otherVersion   string
//		otherFormat    Format
//		expectError    bool
//		errorSubstring string
//	}{
//		{
//			name:         "fuzzy comparison with semantic version",
//			thisVersion:  "1.2.3",
//			otherVersion: "1.2.4",
//			otherFormat:  SemanticFormat,
//			expectError:  false,
//		},
//		{
//			name:         "fuzzy comparison with unknown format",
//			thisVersion:  "1.2.3",
//			otherVersion: "1.2.4",
//			otherFormat:  UnknownFormat,
//			expectError:  false,
//		},
//		{
//			name:         "fuzzy comparison with different format",
//			thisVersion:  "1.2.3",
//			otherVersion: "1.2.3-r4",
//			otherFormat:  ApkFormat,
//			expectError:  false,
//		},
//		{
//			name:         "fuzzy comparison with non-semantic string",
//			thisVersion:  "1.2.3",
//			otherVersion: "abc123",
//			otherFormat:  UnknownFormat,
//			expectError:  false,
//		},
//		{
//			name:         "fuzzy comparison with empty strings",
//			thisVersion:  "1.2.3",
//			otherVersion: "",
//			otherFormat:  UnknownFormat,
//			expectError:  false,
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			thisVer := fuzzyVersion{
//				raw: test.thisVersion,
//			}
//
//			// if thisVersion is semantic-compatible, populate the semVer field (the same way as in NewVersion)
//			if semver, err := NewVersion(test.thisVersion, SemanticFormat); err == nil {
//				s, ok := semver.comparator.(semanticVersion)
//				require.True(t, ok)
//				thisVer.semVer = &s
//			}
//
//			otherVer, err := NewVersion(test.otherVersion, test.otherFormat)
//			require.NoError(t, err)
//
//			result, err := thisVer.Compare(otherVer)
//
//			if test.expectError {
//				require.Error(t, err)
//				if test.errorSubstring != "" {
//					assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
//						"Expected error to contain '%s', got: %v", test.errorSubstring, err)
//				}
//			} else {
//				assert.NoError(t, err)
//				assert.Contains(t, []int{-1, 0, 1}, result, "Expected comparison result to be -1, 0, or 1")
//			}
//		})
//	}
//}
//
//func TestFuzzyVersionCompareEdgeCases(t *testing.T) {
//	tests := []struct {
//		name           string
//		setupFunc      func(tb testing.TB) (*Version, *Version)
//		expectError    require.ErrorAssertionFunc
//		errorSubstring string
//		wantComparison int
//	}{
//		{
//			name: "nil version object",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisVer := &fuzzyVersion{
//					raw: "1.2.3",
//				}
//
//				semver, err := newSemanticVersion("1.2.3", true)
//				require.NoError(t, err)
//				thisVer.semVer = &semver
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, nil
//			},
//			expectError:    require.Error,
//			errorSubstring: "no version provided for comparison",
//		},
//		{
//			name: "semantic format can deal with empty semver object",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisVer := &fuzzyVersion{
//					raw: "1.2.3",
//				}
//
//				semver, err := newSemanticVersion("1.2.3", true)
//				require.NoError(t, err)
//				thisVer.semVer = &semver
//
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: SemanticFormat,
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError, // this is different than other version objects
//			wantComparison: -1,              // 1.2.3 < 1.2.4
//		},
//		{
//			name: "semantic version with nil obj falls back to fuzzy comparison",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisVer := &fuzzyVersion{
//					raw: "1.2.3",
//				}
//
//				semver, err := newSemanticVersion("1.2.3", true)
//				require.NoError(t, err)
//				thisVer.semVer = &semver
//
//				// Create a semantic version with nil obj
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: SemanticFormat,
//					comparator: semanticVersion{
//						obj: nil, // this will trigger the nil check
//					},
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError,
//			wantComparison: -1, // fuzzy comparison: "1.2.3" < "1.2.4"
//		},
//		{
//			name: "fuzzy version with nil semVer falls back to fuzzy comparison",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisVer := &fuzzyVersion{
//					raw:    "1.2.3",
//					semVer: nil, // this will trigger the nil check
//				}
//
//				semver, err := newSemanticVersion("1.2.3", true)
//				require.NoError(t, err)
//
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: SemanticFormat,
//					comparator: semanticVersion{
//						obj: semver.obj,
//					},
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError,
//			wantComparison: -1, // fuzzy comparison: "1.2.3" < "1.2.4"
//		},
//		{
//			name: "fuzzy version with nil semVer.obj falls back to fuzzy comparison",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisVer := &fuzzyVersion{
//					raw: "1.2.3",
//					semVer: &semanticVersion{
//						obj: nil, // this will trigger the nil check
//					},
//				}
//
//				semver, err := newSemanticVersion("1.2.3", true)
//				require.NoError(t, err)
//
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: SemanticFormat,
//					comparator: semanticVersion{
//						obj: semver.obj,
//					},
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError,
//			wantComparison: -1, // fuzzy comparison: "1.2.3" < "1.2.4"
//		},
//		{
//			name: "fuzzy vs fuzzy - other has nil semVer",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisSemver, err := newSemanticVersion("1.2.3", true)
//				require.NoError(t, err)
//
//				thisVer := &fuzzyVersion{
//					raw:    "1.2.3",
//					semVer: &thisSemver,
//				}
//
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: UnknownFormat,
//					comparator: &fuzzyVersion{
//						raw:    "1.2.4",
//						semVer: nil, // this will trigger the nil check
//					},
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError,
//			wantComparison: -1, // fuzzy comparison: "1.2.3" < "1.2.4"
//		},
//		{
//			name: "fuzzy vs fuzzy - other has nil semVer.obj",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisSemver, err := newSemanticVersion("1.2.3", true)
//				require.NoError(t, err)
//
//				thisVer := &fuzzyVersion{
//					raw:    "1.2.3",
//					semVer: &thisSemver,
//				}
//
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: UnknownFormat,
//					comparator: &fuzzyVersion{
//						raw: "1.2.4",
//						semVer: &semanticVersion{
//							obj: nil, // this will trigger the nil check
//						},
//					},
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError,
//			wantComparison: -1, // fuzzy comparison: "1.2.3" < "1.2.4"
//		},
//		{
//			name: "fuzzy vs fuzzy - this has nil semVer",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisVer := &fuzzyVersion{
//					raw:    "1.2.3",
//					semVer: nil, // this will trigger the nil check
//				}
//
//				otherSemver, err := newSemanticVersion("1.2.4", true)
//				require.NoError(t, err)
//
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: UnknownFormat,
//					comparator: &fuzzyVersion{
//						raw:    "1.2.4",
//						semVer: &otherSemver,
//					},
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError,
//			wantComparison: -1, // fuzzy comparison: "1.2.3" < "1.2.4"
//		},
//		{
//			name: "fuzzy vs fuzzy - this has nil semVer.obj",
//			setupFunc: func(t testing.TB) (*Version, *Version) {
//				thisVer := &fuzzyVersion{
//					raw: "1.2.3",
//					semVer: &semanticVersion{
//						obj: nil, // this will trigger the nil check
//					},
//				}
//
//				otherSemver, err := newSemanticVersion("1.2.4", true)
//				require.NoError(t, err)
//
//				otherVer := &Version{
//					Raw:    "1.2.4",
//					Format: UnknownFormat,
//					comparator: &fuzzyVersion{
//						raw:    "1.2.4",
//						semVer: &otherSemver,
//					},
//				}
//
//				return &Version{
//					Raw:        "1.2.3",
//					Format:     UnknownFormat,
//					comparator: thisVer,
//				}, otherVer
//			},
//			expectError:    require.NoError,
//			wantComparison: -1, // fuzzy comparison: "1.2.3" < "1.2.4"
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			if test.expectError == nil {
//				test.expectError = require.NoError
//			}
//			thisVer, otherVer := test.setupFunc(t)
//
//			n, err := thisVer.Compare(otherVer)
//			test.expectError(t, err)
//			if test.errorSubstring != "" {
//				assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
//					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
//			}
//			if err != nil {
//				return
//			}
//			assert.Equal(t, test.wantComparison, n, "Expected comparison result to be %d", test.wantComparison)
//		})
//	}
//}
