package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

func newHttpClient(timeout time.Duration) *http.Client {
	// TODO: Need to test this out
	// Doesn't seem to work as expected
	c := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, timeout)
				if err != nil {
					return nil, err
				}
				return c, nil
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}
	return c
}

// bytes_to_a32 converts the byte slice b to uint32 slice considering
// the bytes to be in big endian order.
func bytes_to_a32(b []byte) ([]uint32, error) {
	length := len(b) + 3
	a := make([]uint32, length/4)
	buf := bytes.NewBuffer(b)
	for i := range a {
		err := binary.Read(buf, binary.BigEndian, &a[i])
		if err != nil {
			return nil, err
		}
	}

	return a, nil
}

// a32_to_bytes converts the uint32 slice a to byte slice where each
// uint32 is decoded in big endian order.
func a32_to_bytes(a []uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Grow(len(a) * 4) // To prevent reallocations in Write
	for _, v := range a {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// base64urlencode encodes byte slice b using base64 url encoding
// without `=` padding.
func base64urlencode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// base64urldecode decodes the byte slice b using unpadded base64 url
// decoding. It also allows the characters from standard base64 to be
// compatible with the mega decoder.
func base64urldecode(s string) ([]byte, error) {
	enc := base64.RawURLEncoding
	// mega base64 decoder accepts the characters from both URLEncoding and StdEncoding
	// though nearly all strings are URL encoded
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return enc.DecodeString(s)
}

// a32_to_base64 converts uint32 slice to base64 encoded byte slice.
func a32_to_base64(a []uint32) (string, error) {
	d, err := a32_to_bytes(a)
	if err != nil {
		return "", err
	}
	return base64urlencode(d), nil
}

// paddnull pads byte slice b such that the size of resulting byte
// slice is a multiple of q.
func paddnull(b []byte, q int) []byte {
	if rem := len(b) % q; rem != 0 {
		l := q - rem

		for i := 0; i < l; i++ {
			b = append(b, 0)
		}
	}

	return b
}

// password_key calculates password hash from the user password.
func password_key(p string) ([]byte, error) {
	a, err := bytes_to_a32(paddnull([]byte(p), 4))
	if err != nil {
		return nil, err
	}

	pkey, err := a32_to_bytes([]uint32{0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56})
	if err != nil {
		return nil, err
	}

	n := (len(a) + 3) / 4

	ciphers := make([]cipher.Block, n)

	for j := 0; j < len(a); j += 4 {
		key := []uint32{0, 0, 0, 0}
		for k := 0; k < 4; k++ {
			if j+k < len(a) {
				key[k] = a[k+j]
			}
		}
		bkey, err := a32_to_bytes(key)
		if err != nil {
			return nil, err
		}
		ciphers[j/4], err = aes.NewCipher(bkey) // Uses AES in ECB mode
		if err != nil {
			return nil, err
		}
	}

	for i := 65536; i > 0; i-- {
		for j := 0; j < n; j++ {
			ciphers[j].Encrypt(pkey, pkey)
		}
	}

	return pkey, nil
}

// stringhash computes generic string hash. Uses k as the key for AES
// cipher.
func stringhash(s string, k []byte) (string, error) {
	a, err := bytes_to_a32(paddnull([]byte(s), 4))
	if err != nil {
		return "", err
	}
	h := []uint32{0, 0, 0, 0}
	for i, v := range a {
		h[i&3] ^= v
	}

	hb, err := a32_to_bytes(h)
	if err != nil {
		return "", err
	}
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	for i := 16384; i > 0; i-- {
		cipher.Encrypt(hb, hb)
	}
	ha, err := bytes_to_a32(paddnull(hb, 4))
	if err != nil {
		return "", err
	}

	return a32_to_base64([]uint32{ha[0], ha[2]})
}

// getMPI returns the length encoded Int and the next slice.
func getMPI(b []byte) (*big.Int, []byte) {
	p := new(big.Int)
	plen := (uint64(b[0])*256 + uint64(b[1]) + 7) >> 3
	p.SetBytes(b[2 : plen+2])
	b = b[plen+2:]
	return p, b
}

// getRSAKey decodes the RSA Key from the byte slice b.
func getRSAKey(b []byte) (*big.Int, *big.Int, *big.Int) {
	p, b := getMPI(b)
	q, b := getMPI(b)
	d, _ := getMPI(b)

	return p, q, d
}

// decryptRSA decrypts message m using RSA private key (p,q,d)
func decryptRSA(m, p, q, d *big.Int) []byte {
	n := new(big.Int)
	r := new(big.Int)
	n.Mul(p, q)
	r.Exp(m, d, n)

	return r.Bytes()
}

// blockDecrypt decrypts using the block cipher blk in ECB mode.
func blockDecrypt(blk cipher.Block, dst, src []byte) error {

	if len(src) > len(dst) || len(src)%blk.BlockSize() != 0 {
		return errors.New("Block decryption failed")
	}

	l := len(src) - blk.BlockSize()

	for i := 0; i <= l; i += blk.BlockSize() {
		blk.Decrypt(dst[i:], src[i:])
	}

	return nil
}

// blockEncrypt encrypts using the block cipher blk in ECB mode.
func blockEncrypt(blk cipher.Block, dst, src []byte) error {

	if len(src) > len(dst) || len(src)%blk.BlockSize() != 0 {
		return errors.New("Block encryption failed")
	}

	l := len(src) - blk.BlockSize()

	for i := 0; i <= l; i += blk.BlockSize() {
		blk.Encrypt(dst[i:], src[i:])
	}

	return nil
}

// decryptSeessionId decrypts the session id using the given private
// key.
func decryptSessionId(privk string, csid string, mk []byte) (string, error) {

	block, err := aes.NewCipher(mk)
	if err != nil {
		return "", err
	}
	pk, err := base64urldecode(privk)
	if err != nil {
		return "", err
	}
	err = blockDecrypt(block, pk, pk)
	if err != nil {
		return "", err
	}

	c, err := base64urldecode(csid)
	if err != nil {
		return "", err
	}

	m, _ := getMPI(c)

	p, q, d := getRSAKey(pk)
	r := decryptRSA(m, p, q, d)

	return base64urlencode(r[:43]), nil

}

// chunkSize describes a size and position of chunk
type chunkSize struct {
	position int64
	size     int
}

func getChunkSizes(size int64) (chunks []chunkSize) {
	p := int64(0)
	for i := 1; size > 0; i++ {
		var chunk int
		if i <= 8 {
			chunk = i * 131072
		} else {
			chunk = 1048576
		}
		if size < int64(chunk) {
			chunk = int(size)
		}
		chunks = append(chunks, chunkSize{position: p, size: chunk})
		p += int64(chunk)
		size -= int64(chunk)
	}
	return chunks
}

// groupChunks merges consecutive chunks into parts of at least size
// bytes, so every part still ends on a chunk boundary
func groupChunks(chunks []chunkSize, size int64) (parts []chunkSize) {
	for _, c := range chunks {
		if n := len(parts); n > 0 && int64(parts[n-1].size) < size {
			parts[n-1].size += c.size
		} else {
			parts = append(parts, c)
		}
	}
	return parts
}

var attrMatch = regexp.MustCompile(`{".*"}`)

func decryptAttr(key []byte, data string) (attr FileAttr, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return attr, err
	}
	iv, err := a32_to_bytes([]uint32{0, 0, 0, 0})
	if err != nil {
		return attr, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	buf := make([]byte, len(data))
	ddata, err := base64urldecode(data)
	if err != nil {
		return attr, err
	}
	mode.CryptBlocks(buf, ddata)

	if string(buf[:4]) == "MEGA" {
		str := strings.TrimRight(string(buf[4:]), "\x00")
		trimmed := attrMatch.FindString(str)
		if trimmed != "" {
			str = trimmed
		}
		err = json.Unmarshal([]byte(str), &attr)
	}
	return attr, err
}

func encryptAttr(key []byte, attr FileAttr) (b string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(attr)
	if err != nil {
		return "", err
	}
	attrib := []byte("MEGA")
	attrib = append(attrib, data...)
	attrib = paddnull(attrib, 16)

	iv, err := a32_to_bytes([]uint32{0, 0, 0, 0})
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(attrib, attrib)

	b = base64urlencode(attrib)
	return b, nil
}

func randString(l int) (string, error) {
	encoding := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"
	b := make([]byte, l)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	enc := base64.NewEncoding(encoding)
	d := make([]byte, enc.EncodedLen(len(b)))
	enc.Encode(d, b)
	d = d[:l]
	return strings.NewReplacer("/", "A", "+", "B").Replace(string(d)), nil
}

// halfCPUCores returns half the number of logical CPU cores available.
// The return value is always at least 1, even if the system reports fewer than 2 cores.
func halfCPUCores() int {
	n := runtime.NumCPU() / 2
	if n < 1 {
		return 1
	}
	return n
}

// newCTR returns the AES-CTR stream used to encrypt and decrypt file
// data starting at offset. Only the first 8 bytes of nonce are used.
func newCTR(block cipher.Block, nonce []byte, offset int64) cipher.Stream {
	iv := make([]byte, 16)
	copy(iv, nonce[:8])
	binary.BigEndian.PutUint64(iv[8:], uint64(offset)/16)
	ctr := cipher.NewCTR(block, iv)
	// the counter addresses 16 byte blocks so skip to offset within one
	skip := make([]byte, offset%16)
	ctr.XORKeyStream(skip, skip)
	return ctr
}

// chunkMAC returns the CBC-MAC of the plaintext of one non-empty chunk
func chunkMAC(block cipher.Block, iv, chunk []byte) []byte {
	mac := make([]byte, 16)
	buf := make([]byte, (len(chunk)+15)&^15) // zero padded
	copy(buf, chunk)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)
	copy(mac, buf[len(buf)-16:])
	return mac
}

// macWriter computes the MAC of each chunk of a file from its
// plaintext, which is written to it in order starting at offset.
//
// The MAC of a chunk is passed to setMAC once its last byte has been
// written. Chunks not written from their start are skipped.
type macWriter struct {
	block  cipher.Block
	iv     []byte
	chunks []chunkSize
	setMAC func(id int, mac []byte)
	pos    int64  // file position of the next byte
	chunk  int    // index of the chunk containing pos
	whole  bool   // set if the current chunk is being written from its start
	buf    []byte // plaintext of the current chunk so far
}

func newMACWriter(block cipher.Block, iv []byte, chunks []chunkSize, offset int64, setMAC func(id int, mac []byte)) *macWriter {
	chunk := sort.Search(len(chunks), func(i int) bool {
		return chunks[i].position+int64(chunks[i].size) > offset
	})
	return &macWriter{
		block:  block,
		iv:     iv,
		chunks: chunks,
		setMAC: setMAC,
		pos:    offset,
		chunk:  chunk,
		whole:  chunk < len(chunks) && chunks[chunk].position == offset,
	}
}

// Write feeds plaintext b into the chunk MACs. It never returns an
// error.
func (w *macWriter) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 && w.chunk < len(w.chunks) {
		chunkEnd := w.chunks[w.chunk].position + int64(w.chunks[w.chunk].size)
		k := int(min(int64(len(b)), chunkEnd-w.pos))
		if w.whole {
			w.buf = append(w.buf, b[:k]...)
		}
		w.pos += int64(k)
		b = b[k:]
		if w.pos == chunkEnd {
			if w.whole {
				w.setMAC(w.chunk, chunkMAC(w.block, w.iv, w.buf))
			}
			w.buf = w.buf[:0]
			w.whole = true
			w.chunk++
		}
	}
	return n, nil
}

// progressWriter sends the size of each write to a progress channel
type progressWriter chan int

func (p progressWriter) Write(b []byte) (int, error) {
	p <- len(b)
	return len(b), nil
}

// withProgress returns r, reporting the size of each read to progress
// if it is not nil
func withProgress(r io.Reader, progress *chan int) io.Reader {
	if progress == nil {
		return r
	}
	return io.TeeReader(r, progressWriter(*progress))
}

// statusError returns the error for a transfer request which got a
// status other than 200
func statusError(resp *http.Response) error {
	if resp.StatusCode == 509 {
		// the transfer quota is exceeded
		return EOVERQUOTA
	}
	return errors.New("Http Status: " + resp.Status)
}

// withRetries calls fn until it succeeds, the configured retries are
// used up or ctx is done, backing off between attempts. EOVERQUOTA is
// not retried as it lasts far longer than the backoff.
func (m *Mega) withRetries(ctx context.Context, what string, fn func() error) (err error) {
	sleepTime := minSleepTime // initial backoff time
	for retry := 0; ; retry++ {
		err = fn()
		if err == nil || errors.Is(err, EOVERQUOTA) || retry >= m.retries || ctx.Err() != nil {
			return err
		}
		m.debugf("%s: retry %d/%d: %v", what, retry+1, m.retries, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleepTime):
		}
		sleepTime = min(2*sleepTime, maxSleepTime)
	}
}
