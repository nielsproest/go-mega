package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
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

	ukey := make([]uint32, 6)
	if err := binary.Read(rand.Reader, binary.BigEndian, ukey); err != nil {
		return nil, err
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
	chunk_macs := make([][]byte, len(chunks))

	// File size is zero
	// Do one empty request to get the completion handle. The MAC of
	// the empty chunk is all zeros.
	if len(chunks) == 0 {
		chunks = append(chunks, chunkSize{position: 0, size: 0})
		chunk_macs = append(chunk_macs, make([]byte, 16))
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
		chunk_macs:        chunk_macs,
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
func (u *Upload) UploadChunk(id int, chunk []byte) error {
	_, chk_size, err := u.ChunkLocation(id)
	if err != nil {
		return err
	}
	if len(chunk) != chk_size {
		return errors.New("upload chunk is wrong size")
	}
	return u.UploadFrom(context.Background(), id, 1, bytes.NewReader(chunk))
}

// setChunkMAC records the MAC of chunk id
func (u *Upload) setChunkMAC(id int, mac []byte) {
	u.mutex.Lock()
	u.chunk_macs[id] = mac
	u.mutex.Unlock()
}

// postRange uploads the encrypted data at offset, retrying as
// configured, and records the completion handle if the server returns
// one.
func (u *Upload) postRange(ctx context.Context, offset int64, data []byte) error {
	url := fmt.Sprintf("%s/%d", u.uploadUrl, offset)
	what := fmt.Sprintf("%s: upload %d+%d", u.name, offset, len(data))
	return u.m.withRetries(ctx, what, func() error {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
		if err != nil {
			return err
		}
		resp, err := u.m.client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			return statusError(resp)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		// errors are sent as a negative number
		if code, err := strconv.Atoi(string(body)); err == nil && code < 0 {
			return parseError(ErrorMsg(code))
		}
		if len(body) > 0 {
			u.mutex.Lock()
			u.completion_handle = body
			u.mutex.Unlock()
		}
		return nil
	})
}

// UploadFrom uploads n chunks starting at chunk id, or the chunks from
// id to the end of the file if n < 0, reading their contents from in.
//
// The data is sent in HTTP requests of at least the configured upload
// request size (see SetUploadRequestSize) ending on chunk boundaries,
// using up to the configured number of upload workers concurrently.
// Failed requests are retried. Up to (workers + 1) requests' worth of
// data is buffered.
//
// Finish may be called once every chunk has been uploaded.
func (u *Upload) UploadFrom(ctx context.Context, id, n int, in io.Reader) error {
	if id < 0 || id >= len(u.chunks) {
		return EARGS
	}
	offset := u.chunks[id].position
	chunks := u.chunks[id:]
	if n >= 0 && n < len(chunks) {
		chunks = chunks[:n]
	}
	mac := newMACWriter(u.aes_block, u.iv, u.chunks, offset, u.setChunkMAC)
	// MAC the plaintext, then encrypt it
	in = cipher.StreamReader{S: newCTR(u.aes_block, u.kiv, offset), R: io.TeeReader(in, mac)}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(u.m.ul_workers, 1))
	for _, part := range groupChunks(chunks, u.m.ul_reqsize) {
		if gctx.Err() != nil {
			break
		}
		data := make([]byte, part.size)
		if _, err := io.ReadFull(in, data); err != nil {
			cancel()
			_ = g.Wait()
			return err
		}
		g.Go(func() error {
			return u.postRange(gctx, part.position, data)
		})
	}
	return g.Wait()
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

	err = u.UploadFrom(context.Background(), 0, -1, withProgress(infile, progress))
	if err != nil {
		return nil, err
	}

	return u.Finish()
}
