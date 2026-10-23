package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Download contains the internal state of a download
type Download struct {
	m           *Mega
	src         *Node
	aes_block   cipher.Block
	iv          []byte
	mac_enc     cipher.BlockMode
	mutex       sync.Mutex // to protect the following
	resourceUrl string
	chunks      []chunkSize
	chunk_macs  [][]byte
}

// Create a new Download from the src Node
//
// Call Chunks to find out how many chunks there are, then for id =
// 0..chunks-1 call DownloadChunk.  Finally call Finish() to receive
// the error status.
func (m *Mega) NewDownload(src *Node) (*Download, error) {
	if src == nil {
		return nil, EARGS
	}

	var msg [1]DownloadMsg
	var res [1]DownloadResp

	m.FS.mutex.Lock()
	msg[0].Cmd = "g"
	msg[0].G = 1
	msg[0].N = src.hash
	if m.config.https {
		msg[0].SSL = 2
	}
	key := src.meta.key
	m.FS.mutex.Unlock()

	request, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	result, err := m.api_request(request)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return nil, err
	}

	// DownloadResp has an embedded error in it for some reason
	if res[0].Err != 0 {
		return nil, parseError(res[0].Err)
	}

	_, err = decryptAttr(key, res[0].Attr)
	if err != nil {
		return nil, err
	}

	chunks := getChunkSizes(int64(res[0].Size))

	aes_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mac_enc := cipher.NewCBCEncrypter(aes_block, zero_iv)
	m.FS.mutex.Lock()
	t, err := bytes_to_a32(src.meta.iv)
	m.FS.mutex.Unlock()
	if err != nil {
		return nil, err
	}
	iv, err := a32_to_bytes([]uint32{t[0], t[1], t[0], t[1]})
	if err != nil {
		return nil, err
	}

	downloadUrl := res[0].G
	if m.config.https && strings.HasPrefix(downloadUrl, "http://") {
		downloadUrl = "https://" + strings.TrimPrefix(downloadUrl, "http://")
	}

	d := &Download{
		m:           m,
		src:         src,
		resourceUrl: downloadUrl,
		aes_block:   aes_block,
		iv:          iv,
		mac_enc:     mac_enc,
		chunks:      chunks,
		chunk_macs:  make([][]byte, len(chunks)),
	}
	return d, nil
}

// Chunks returns The number of chunks in the download.
func (d *Download) Chunks() int {
	return len(d.chunks)
}

// ChunkLocation returns the position in the file and the size of the chunk
func (d *Download) ChunkLocation(id int) (position int64, size int, err error) {
	if id < 0 || id >= len(d.chunks) {
		return 0, 0, EARGS
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.chunks[id].position, d.chunks[id].size, nil
}

// DownloadChunk gets a chunk with the given number and update the
// mac, returning the position in the file of the chunk
func (d *Download) DownloadChunk(id int) (chunk []byte, err error) {
	chk_start, chk_size, err := d.ChunkLocation(id)
	if err != nil {
		return nil, err
	}
	in, err := d.NewReader(context.Background(), chk_start, int64(chk_size))
	if err != nil {
		return nil, err
	}
	defer func() { _ = in.Close() }()
	chunk = make([]byte, chk_size)
	if _, err = io.ReadFull(in, chunk); err != nil {
		return nil, err
	}
	return chunk, nil
}

// setChunkMAC records the MAC of chunk id
func (d *Download) setChunkMAC(id int, mac []byte) {
	d.mutex.Lock()
	d.chunk_macs[id] = mac
	d.mutex.Unlock()
}

// fetchRange reads the encrypted bytes from start up to but not
// including end, retrying as configured.
func (d *Download) fetchRange(ctx context.Context, start, end int64) (data []byte, err error) {
	what := fmt.Sprintf("%s: download %d-%d", d.src.name, start, end-1)
	err = d.m.withRetries(ctx, what, func() error {
		d.mutex.Lock()
		base := d.resourceUrl
		d.mutex.Unlock()
		url := fmt.Sprintf("%s/%d-%d", base, start, end-1)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}
		resp, err := d.m.client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == 403 || resp.StatusCode == 404 {
			// the download URL has expired so get a new one to retry with
			if err := d.refreshURL(base); err != nil {
				return err
			}
		}
		if resp.StatusCode != 200 {
			return statusError(resp)
		}
		if resp.ContentLength >= 0 && resp.ContentLength != end-start {
			return fmt.Errorf("wrong size for downloaded range: %d bytes", resp.ContentLength)
		}
		data = make([]byte, end-start)
		_, err = io.ReadFull(resp.Body, data)
		return err
	})
	return data, err
}

// refreshURL replaces the download URL with a new one from the API,
// unless another request has already replaced stale
func (d *Download) refreshURL(stale string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.resourceUrl != stale {
		return nil
	}
	fresh, err := d.m.NewDownload(d.src)
	if err != nil {
		return err
	}
	d.resourceUrl = fresh.resourceUrl
	return nil
}

// NewReader returns a reader for the decrypted file contents starting
// at offset for length bytes, or to the end of the file if length < 0.
//
// The range is fetched with HTTP requests of up to the configured
// request size (see SetDownloadRequestSize) using up to the configured
// number of download workers concurrently. The first request is small
// and both ramp up as the data is read, so reading only the start of a
// range stays cheap. Failed requests are retried. Up to workers
// requests' worth of data is buffered.
//
// The MAC of every chunk read completely is recorded, so Finish can
// verify the file once all of it has been read. The reader must be
// closed after use.
func (d *Download) NewReader(ctx context.Context, offset, length int64) (io.ReadCloser, error) {
	var size int64
	if n := len(d.chunks); n > 0 {
		size = d.chunks[n-1].position + int64(d.chunks[n-1].size)
	}
	if offset < 0 || offset > size {
		return nil, EARGS
	}
	end := size
	if length >= 0 && offset+length < end {
		end = offset + length
	}
	ctr := newCTR(d.aes_block, d.src.meta.iv, offset)
	mac := newMACWriter(d.aes_block, d.iv, d.chunks, offset, d.setChunkMAC)
	in := newParallelReader(ctx, d, offset, end, max(d.m.dl_workers, 1), d.m.dl_reqsize)
	// decrypt the stream, then MAC the plaintext as it is read
	return struct {
		io.Reader
		io.Closer
	}{io.TeeReader(cipher.StreamReader{S: ctr, R: in}, mac), in}, nil
}

// firstRequestSize is the size of the first request a parallelReader
// makes, doubling with each request up to the request size
const firstRequestSize = 1024 * 1024

// parallelReader returns the encrypted bytes of a range in order,
// fetching them in parts of up to reqsize with up to workers concurrent
// HTTP requests
type parallelReader struct {
	*io.PipeReader
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// rangePart is the result of fetching one part
type rangePart struct {
	data []byte
	err  error
}

func newParallelReader(ctx context.Context, d *Download, start, end int64, workers int, reqsize int64) *parallelReader {
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	p := &parallelReader{PipeReader: pr, cancel: cancel}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		// stop the other requests if one fails
		defer p.cancel()
		// requests in flight, oldest first
		inflight := make(chan chan rangePart, workers)
		size, limit := min(firstRequestSize, reqsize), 1
		for pos := start; pos < end || len(inflight) > 0; {
			for pos < end && len(inflight) < limit {
				next := min(pos+size, end)
				inflight <- p.fetch(ctx, d, pos, next)
				pos = next
				size = min(2*size, reqsize)
			}
			part := <-<-inflight
			if part.err == nil {
				_, part.err = pw.Write(part.data)
			}
			if part.err != nil {
				_ = pw.CloseWithError(part.err)
				return
			}
			limit = min(limit+1, workers)
		}
		_ = pw.Close()
	}()
	return p
}

// fetch fetches a range in the background, returning a channel which
// receives the result
func (p *parallelReader) fetch(ctx context.Context, d *Download, start, end int64) chan rangePart {
	result := make(chan rangePart, 1)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		data, err := d.fetchRange(ctx, start, end)
		result <- rangePart{data: data, err: err}
	}()
	return result
}

// Close stops any outstanding requests and waits for them to finish
func (p *parallelReader) Close() error {
	p.cancel()
	_ = p.PipeReader.Close()
	p.wg.Wait()
	return nil
}

// Finish checks the accumulated MAC for each block.
//
// If all the chunks weren't downloaded then it will just return nil
func (d *Download) Finish() (err error) {
	// Can't check a 0 sized file
	if len(d.chunk_macs) == 0 {
		return nil
	}
	mac_data := make([]byte, 16)
	for _, v := range d.chunk_macs {
		// If a chunk_macs hasn't been set then the whole file
		// wasn't downloaded and we can't check it
		if v == nil {
			return nil
		}
		d.mac_enc.CryptBlocks(mac_data, v)
	}

	tmac, err := bytes_to_a32(mac_data)
	if err != nil {
		return err
	}
	btmac, err := a32_to_bytes([]uint32{tmac[0] ^ tmac[1], tmac[2] ^ tmac[3]})
	if err != nil {
		return err
	}
	if !bytes.Equal(btmac, d.src.meta.mac) {
		return EMACMISMATCH
	}

	return nil
}

// Download file from filesystem reporting progress if not nil
func (m *Mega) DownloadFile(src *Node, dstpath string, progress *chan int) error {
	defer func() {
		if progress != nil {
			close(*progress)
		}
	}()

	d, err := m.NewDownload(src)
	if err != nil {
		return err
	}

	_, err = os.Stat(dstpath)
	if os.IsExist(err) {
		err = os.Remove(dstpath)
		if err != nil {
			return err
		}
	}

	outfile, err := os.OpenFile(dstpath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	in, err := d.NewReader(context.Background(), 0, -1)
	if err == nil {
		_, err = io.Copy(outfile, withProgress(in, progress))
		_ = in.Close()
	}

	closeErr := outfile.Close()
	if err != nil {
		_ = os.Remove(dstpath)
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	return d.Finish()
}
