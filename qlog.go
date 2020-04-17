package libp2pquic

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"time"
)

var qlogDir string

func init() {
	qlogDir = os.Getenv("QLOGDIR")
}

func getLogWriterFor(role string) func([]byte) io.WriteCloser {
	if len(qlogDir) == 0 {
		return nil
	}
	return func(connID []byte) io.WriteCloser {
		// create the QLOGDIR, if it doesn't exist
		if err := os.MkdirAll(qlogDir, 0777); err != nil {
			log.Errorf("creating the QLOGDIR failed: %s", err)
			return nil
		}
		return newQlogger(role, connID)
	}
}

type qlogger struct {
	f        *os.File // QLOGDIR/.log_xxx.qlog.gz.swp
	filename string   // QLOGDIR/log_xxx.qlog.gz
	io.WriteCloser
}

func newQlogger(role string, connID []byte) io.WriteCloser {
	t := time.Now().UTC().Format("2006-01-02T15-04-05.999999999UTC")
	finalFilename := fmt.Sprintf("%s%clog_%s_%s_%x.qlog.gz", qlogDir, os.PathSeparator, t, role, connID)
	filename := fmt.Sprintf("%s%c.log_%s_%s_%x.qlog.gz.swp", qlogDir, os.PathSeparator, t, role, connID)
	f, err := os.Create(filename)
	if err != nil {
		log.Errorf("unable to create qlog file %s: %s", filename, err)
		return nil
	}
	gz := gzip.NewWriter(f)
	return &qlogger{
		f:           f,
		filename:    finalFilename,
		WriteCloser: newBufferedWriteCloser(bufio.NewWriter(gz), gz),
	}
}

func (l *qlogger) Close() error {
	if err := l.WriteCloser.Close(); err != nil {
		return err
	}
	path := l.f.Name()
	if err := l.f.Close(); err != nil {
		return err
	}
	return os.Rename(path, l.filename)
}

type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

func newBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{
		Writer: writer,
		Closer: closer,
	}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}
