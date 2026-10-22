package mega

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Upload contains the internal state of a upload
type Upload struct {
	m                 *Mega
	parenthash        string
	name              string
	uploadUrl         string
	aes_block         cipher.Block
	iv                []byte
	kiv               []byte
	mac_enc           cipher.BlockMode
	kbytes            []byte
	ukey              []uint32
	mutex             sync.Mutex // to protect the following
	chunks            []chunkSize
	chunk_macs        [][]byte
	completion_handle []byte
}

// Create a new Upload of name into parent of fileSize
//
// Call Chunks to find out how many chunks there are, then for id =
// 0..chunks-1 Call ChunkLocation then UploadChunk.  Finally call
// Finish() to receive the error status and the *Node.
func (m *Mega) NewUpload(parent *Node, name string, fileSize int64) (*Upload, error) {
	if parent == nil {
		return nil, EARGS
	}

	var msg [1]UploadMsg
	var res [1]UploadResp
	parenthash := parent.GetHash()

	msg[0].Cmd = "u"
	msg[0].S = fileSize
	if m.config.https {
		msg[0].SSL = 2
	}

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

	ukey := []uint32{0, 0, 0, 0, 0, 0}
	for i := range ukey {
		ukey[i] = uint32(mrand.Int31())

	}

	kbytes, err := a32_to_bytes(ukey[:4])
	if err != nil {
		return nil, err
	}
	kiv, err := a32_to_bytes([]uint32{ukey[4], ukey[5], 0, 0})
	if err != nil {
		return nil, err
	}
	aes_block, err := aes.NewCipher(kbytes)
	if err != nil {
		return nil, err
	}

	mac_enc := cipher.NewCBCEncrypter(aes_block, zero_iv)
	iv, err := a32_to_bytes([]uint32{ukey[4], ukey[5], ukey[4], ukey[5]})
	if err != nil {
		return nil, err
	}

	chunks := getChunkSizes(fileSize)

	// File size is zero
	// Do one empty request to get the completion handle
	if len(chunks) == 0 {
		chunks = append(chunks, chunkSize{position: 0, size: 0})
	}

	uploadUrl := res[0].P
	if m.config.https && strings.HasPrefix(uploadUrl, "http://") {
		uploadUrl = "https://" + strings.TrimPrefix(uploadUrl, "http://")
	}

	u := &Upload{
		m:                 m,
		parenthash:        parenthash,
		name:              name,
		uploadUrl:         uploadUrl,
		aes_block:         aes_block,
		iv:                iv,
		kiv:               kiv,
		mac_enc:           mac_enc,
		kbytes:            kbytes,
		ukey:              ukey,
		chunks:            chunks,
		chunk_macs:        make([][]byte, len(chunks)),
		completion_handle: []byte{},
	}
	return u, nil
}

// Chunks returns The number of chunks in the upload.
func (u *Upload) Chunks() int {
	return len(u.chunks)
}

// ChunkLocation returns the position in the file and the size of the chunk
func (u *Upload) ChunkLocation(id int) (position int64, size int, err error) {
	if id < 0 || id >= len(u.chunks) {
		return 0, 0, EARGS
	}
	return u.chunks[id].position, u.chunks[id].size, nil
}

// UploadChunk uploads the chunk of id
func (u *Upload) UploadChunk(id int, chunk []byte) (err error) {
	chk_start, chk_size, err := u.ChunkLocation(id)
	if err != nil {
		return err
	}
	if len(chunk) != chk_size {
		return errors.New("upload chunk is wrong size")
	}
	ctr_iv, err := bytes_to_a32(u.kiv)
	if err != nil {
		return err
	}
	ctr_iv[2] = uint32(uint64(chk_start) / 0x1000000000)
	ctr_iv[3] = uint32(chk_start / 0x10)
	bctr_iv, err := a32_to_bytes(ctr_iv)
	if err != nil {
		return err
	}
	ctr_aes := cipher.NewCTR(u.aes_block, bctr_iv)

	enc := cipher.NewCBCEncrypter(u.aes_block, u.iv)

	i := 0
	block := make([]byte, 16)
	paddedchunk := paddnull(chunk, 16)
	for i = 0; i < len(paddedchunk); i += 16 {
		copy(block[0:16], paddedchunk[i:i+16])
		enc.CryptBlocks(block, block)
	}

	var rsp *http.Response
	var req *http.Request
	ctr_aes.XORKeyStream(chunk, chunk)
	chk_url := fmt.Sprintf("%s/%d", u.uploadUrl, chk_start)

	sleepTime := minSleepTime // initial backoff time
	for retry := 0; retry < u.m.retries+1; retry++ {
		reader := bytes.NewBuffer(chunk)
		req, err = http.NewRequest("POST", chk_url, reader)
		if err != nil {
			return err
		}
		rsp, err = u.m.client.Do(req)
		if err == nil {
			if rsp.StatusCode == 200 {
				break
			}
			err = errors.New("Http Status: " + rsp.Status)
			_ = rsp.Body.Close()
		}
		u.m.debugf("%s: Retry upload chunk %d/%d: %v", u.name, retry, u.m.retries, err)
		backOffSleep(&sleepTime)
	}
	if err != nil {
		return err
	}
	if rsp == nil {
		return errors.New("retries exceeded")
	}

	chunk_resp, err := io.ReadAll(rsp.Body)
	if err != nil {
		_ = rsp.Body.Close()
		return err
	}

	err = rsp.Body.Close()
	if err != nil {
		return err
	}

	if !bytes.Equal(chunk_resp, nil) {
		u.mutex.Lock()
		u.completion_handle = chunk_resp
		u.mutex.Unlock()
	}

	// Update chunk MACs on success only
	u.mutex.Lock()
	if len(u.chunk_macs) > 0 {
		u.chunk_macs[id] = make([]byte, 16)
		copy(u.chunk_macs[id], block)
	}
	u.mutex.Unlock()

	return nil
}

// Finish completes the upload and returns the created node
func (u *Upload) Finish() (node *Node, err error) {
	mac_data := make([]byte, 16)
	for _, v := range u.chunk_macs {
		u.mac_enc.CryptBlocks(mac_data, v)
	}

	t, err := bytes_to_a32(mac_data)
	if err != nil {
		return nil, err
	}
	meta_mac := []uint32{t[0] ^ t[1], t[2] ^ t[3]}

	attr := FileAttr{u.name}

	attr_data, err := encryptAttr(u.kbytes, attr)
	if err != nil {
		return nil, err
	}

	key := []uint32{u.ukey[0] ^ u.ukey[4], u.ukey[1] ^ u.ukey[5],
		u.ukey[2] ^ meta_mac[0], u.ukey[3] ^ meta_mac[1],
		u.ukey[4], u.ukey[5], meta_mac[0], meta_mac[1]}

	buf, err := a32_to_bytes(key)
	if err != nil {
		return nil, err
	}
	master_aes, err := aes.NewCipher(u.m.k)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(master_aes, zero_iv)
	enc.CryptBlocks(buf[:16], buf[:16])
	enc = cipher.NewCBCEncrypter(master_aes, zero_iv)
	enc.CryptBlocks(buf[16:], buf[16:])

	var cmsg [1]UploadCompleteMsg
	var cres [1]UploadCompleteResp

	cmsg[0].Cmd = "p"
	cmsg[0].T = u.parenthash
	cmsg[0].N[0].H = string(u.completion_handle)
	cmsg[0].N[0].T = FILE
	cmsg[0].N[0].A = attr_data
	cmsg[0].N[0].K = base64urlencode(buf)

	request, err := json.Marshal(cmsg)
	if err != nil {
		return nil, err
	}
	result, err := u.m.api_request(request)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &cres)
	if err != nil {
		return nil, err
	}

	u.m.FS.mutex.Lock()
	defer u.m.FS.mutex.Unlock()
	return u.m.addFSNode(cres[0].F[0])
}

// Upload a file to the filesystem
func (m *Mega) UploadFile(srcpath string, parent *Node, name string, progress *chan int) (node *Node, err error) {
	defer func() {
		if progress != nil {
			close(*progress)
		}
	}()

	var infile *os.File
	var fileSize int64

	info, err := os.Stat(srcpath)
	if err == nil {
		fileSize = info.Size()
	}

	infile, err = os.OpenFile(srcpath, os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}
	defer func() {
		e := infile.Close()
		if err == nil {
			err = e
		}
	}()

	if name == "" {
		name = filepath.Base(srcpath)
	}

	u, err := m.NewUpload(parent, name, fileSize)
	if err != nil {
		return nil, err
	}

	workch := make(chan int)
	errch := make(chan error, m.ul_workers)
	wg := sync.WaitGroup{}

	// Fire chunk upload workers
	for w := 0; w < m.ul_workers; w++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for id := range workch {
				chk_start, chk_size, err := u.ChunkLocation(id)
				if err != nil {
					errch <- err
					return
				}
				chunk := make([]byte, chk_size)
				n, err := infile.ReadAt(chunk, chk_start)
				if err != nil && err != io.EOF {
					errch <- err
					return
				}
				if n != len(chunk) {
					errch <- errors.New("chunk too short")
					return
				}

				err = u.UploadChunk(id, chunk)
				if err != nil {
					errch <- err
					return
				}

				if progress != nil {
					*progress <- chk_size
				}
			}
		}()
	}

	// Place chunk download jobs to chan
	err = nil
	for id := 0; id < u.Chunks() && err == nil; {
		select {
		case workch <- id:
			id++
		case err = <-errch:
		}
	}

	close(workch)

	wg.Wait()

	if err != nil {
		return nil, err
	}

	return u.Finish()
}
