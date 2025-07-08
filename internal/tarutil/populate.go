package tarutil

// PopulateWithPaths creates a compressed tar from the given paths.
func PopulateWithPaths(tarPath string, filePaths ...string) error {
	w, err := NewWriter(tarPath)
	if err != nil {
		return err
	}
	defer w.Close()

	for _, entry := range NewEntryFromFilePaths(filePaths...) {
		if err := w.WriteEntry(entry); err != nil {
			return err
		}
	}

	return nil
}
