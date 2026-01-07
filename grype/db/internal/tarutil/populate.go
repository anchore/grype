package tarutil

// PopulateWithPaths creates a compressed tar from the given paths.
func PopulateWithPaths(tarPath string, filePaths ...string) error {
	return PopulateWithPathsAndCompressors(tarPath, nil, filePaths...)
}

// PopulateWithPathsAndCompressors creates a compressed tar from the given paths using custom compressor commands.
func PopulateWithPathsAndCompressors(tarPath string, compressorCommands map[string]string, filePaths ...string) error {
	w, err := NewWriterWithCompressors(tarPath, compressorCommands)
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
