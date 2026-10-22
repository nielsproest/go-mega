package mega

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
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
	resourceUrl string
	aes_block   cipher.Block
	iv          []byte
	mac_enc     cipher.BlockMode
	mutex       sync.Mutex // to protect the following
	chunks      []chunkSize
	chunk_macs  [][]byte
}

// an all nil IV for mac calculations
var zero_iv = make([]byte, 16)

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
	if id < 0 || id >= len(d.chunks) {
		return nil, EARGS
	}

	chk_start, chk_size, err := d.ChunkLocation(id)
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	chunk_url := fmt.Sprintf("%s/%d-%d", d.resourceUrl, chk_start, chk_start+int64(chk_size)-1)
	sleepTime := minSleepTime // initial backoff time
	for retry := 0; retry < d.m.retries+1; retry++ {
		resp, err = d.m.client.Get(chunk_url)
		if err == nil {
			if resp.StatusCode == 200 {
				break
			}
			err = errors.New("Http Status: " + resp.Status)
			_ = resp.Body.Close()
		}
		d.m.debugf("%s: Retry download chunk %d/%d: %v", d.src.name, retry, d.m.retries, err)
		backOffSleep(&sleepTime)
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("retries exceeded")
	}

	chunk, err = io.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}

	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	// body is read and closed here

	if len(chunk) != chk_size {
		return nil, errors.New("wrong size for downloaded chunk")
	}

	// Decrypt the block
	ctr_iv, err := bytes_to_a32(d.src.meta.iv)
	if err != nil {
		return nil, err
	}
	ctr_iv[2] = uint32(uint64(chk_start) / 0x1000000000)
	ctr_iv[3] = uint32(chk_start / 0x10)
	bctr_iv, err := a32_to_bytes(ctr_iv)
	if err != nil {
		return nil, err
	}
	ctr_aes := cipher.NewCTR(d.aes_block, bctr_iv)
	ctr_aes.XORKeyStream(chunk, chunk)

	// Update the chunk_macs
	enc := cipher.NewCBCEncrypter(d.aes_block, d.iv)
	i := 0
	block := make([]byte, 16)
	paddedChunk := paddnull(chunk, 16)
	for i = 0; i < len(paddedChunk); i += 16 {
		enc.CryptBlocks(block, paddedChunk[i:i+16])
	}

	d.mutex.Lock()
	if len(d.chunk_macs) > 0 {
		d.chunk_macs[id] = make([]byte, 16)
		copy(d.chunk_macs[id], block)
	}
	d.mutex.Unlock()

	return chunk, nil
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

	workch := make(chan int)
	errch := make(chan error, m.dl_workers)
	wg := sync.WaitGroup{}

	// Fire chunk download workers
	for w := 0; w < m.dl_workers; w++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// Wait for work blocked on channel
			for id := range workch {
				chunk, err := d.DownloadChunk(id)
				if err != nil {
					errch <- err
					return
				}

				chk_start, _, err := d.ChunkLocation(id)
				if err != nil {
					errch <- err
					return
				}

				_, err = outfile.WriteAt(chunk, chk_start)
				if err != nil {
					errch <- err
					return
				}

				if progress != nil {
					*progress <- len(chunk)
				}
			}
		}()
	}

	// Place chunk download jobs to chan
	err = nil
	for id := 0; id < d.Chunks() && err == nil; {
		select {
		case workch <- id:
			id++
		case err = <-errch:
		}
	}
	close(workch)

	wg.Wait()

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
