package tarutil

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/google/shlex"
	"github.com/klauspost/compress/flate"

	"github.com/anchore/grype/internal/log"
)

var ErrUnsupportedArchiveSuffix = fmt.Errorf("archive name has an unsupported suffix")

var _ Writer = (*writer)(nil)

type writer struct {
	compressor io.WriteCloser
	writer     *tar.Writer
}

// NewWriter creates a new tar writer that writes to the specified archive path. Supports .tar.gz, .tar.zst, .tar.xz, and .tar file extensions.
func NewWriter(archivePath string) (Writer, error) {
	return NewWriterWithCompressors(archivePath, nil)
}

// NewWriterWithCompressors creates a new tar writer with custom compressor commands. If compressorCommands is nil or empty, it uses default commands.
func NewWriterWithCompressors(archivePath string, compressorCommands map[string]string) (Writer, error) {
	w, err := newCompressorWithCommands(archivePath, compressorCommands)
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(w)

	return &writer{
		compressor: w,
		writer:     tw,
	}, nil
}

func newCompressorWithCommands(archivePath string, compressorCommands map[string]string) (io.WriteCloser, error) {
	archive, err := os.Create(archivePath)
	if err != nil {
		return nil, err
	}

	// check for custom compressor command first
	for ext, cmd := range compressorCommands {
		if strings.HasSuffix(archivePath, "."+ext) {
			log.Debugf("using custom compressor command for %s: %s", ext, cmd)
			return newShellCompressor(cmd, archive)
		}
	}
	log.Debugf("no custom compressor command found for %s, using default", archivePath)

	// fall back to default compressor commands
	switch {
	case strings.HasSuffix(archivePath, ".tar.gz"):
		return gzip.NewWriterLevel(archive, flate.BestCompression)
	case strings.HasSuffix(archivePath, ".tar.zst"):
		// note: since we're using --ultra this tends to have a high memory usage at decompression time
		// For ~700 MB payload that is compressing down to ~60 MB, that would need ~130 MB of memory (--ultra -22)
		// for the same payload compressing down to ~65MB, that would need ~70MB of memory (--ultra -21)
		return newShellCompressor("zstd -T0 -22 --ultra -c -vv", archive)
	case strings.HasSuffix(archivePath, ".tar.xz"):
		return newShellCompressor("xz -9 --threads=0 -c -vv", archive)
	case strings.HasSuffix(archivePath, ".tar"):
		return archive, nil
	}
	return nil, ErrUnsupportedArchiveSuffix
}

// shellCompressor wraps the stdin pipe of an external compression process and ensures proper cleanup.
type shellCompressor struct {
	cmd  *exec.Cmd
	pipe io.WriteCloser
}

func newShellCompressor(c string, archive io.Writer) (*shellCompressor, error) {
	args, err := shlex.Split(c)
	if err != nil {
		return nil, fmt.Errorf("unable to parse command: %w", err)
	}
	binary := args[0]

	binPath, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("unable to find binary %q: %w", binary, err)
	}
	if binPath == "" {
		return nil, fmt.Errorf("unable to find binary %q in PATH", binary)
	}

	args = args[1:]
	cmd := exec.Command(binary, args...)
	log.Debug(strings.Join(cmd.Args, " "))
	cmd.Stdout = archive

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("unable to create stderr pipe: %w", err)
	}

	pipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("unable to create stdin pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("unable to start process: %w", err)
	}

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Debugf("[%s] %s", binary, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Errorf("[%s] error reading stderr: %v", binary, err)
		}
	}()

	return &shellCompressor{
		cmd:  cmd,
		pipe: pipe,
	}, nil
}

func (sc *shellCompressor) Write(p []byte) (int, error) {
	return sc.pipe.Write(p)
}

func (sc *shellCompressor) Close() error {
	if err := sc.pipe.Close(); err != nil {
		return fmt.Errorf("unable to close compression stdin pipe: %w", err)
	}
	if err := sc.cmd.Wait(); err != nil {
		return fmt.Errorf("compression process error: %w", err)
	}
	return nil
}

func (w *writer) WriteEntry(entry Entry) error {
	return entry.writeEntry(w.writer)
}

func (w *writer) Close() error {
	if w.writer != nil {
		err := w.writer.Close()
		w.writer = nil
		if err != nil {
			return fmt.Errorf("unable to close tar writer: %w", err)
		}
	}

	if w.compressor != nil {
		err := w.compressor.Close()
		w.compressor = nil
		return err
	}

	return nil
}
