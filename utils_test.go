package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestGetChunkSizes(t *testing.T) {
	const k = 1024
	for _, test := range []struct {
		size int64
		want []chunkSize
	}{
		{
			size: 0,
			want: []chunkSize(nil),
		},
		{
			size: 1,
			want: []chunkSize{
				{0, 1},
			},
		},
		{
			size: 128*k - 1,
			want: []chunkSize{
				{0, 128*k - 1},
			},
		},
		{
			size: 128 * k,
			want: []chunkSize{
				{0, 128 * k},
			},
		},
		{
			size: 128*k + 1,
			want: []chunkSize{
				{0, 128 * k},
				{128 * k, 1},
			},
		},
		{
			size: 384*k - 1,
			want: []chunkSize{
				{0, 128 * k},
				{128 * k, 256*k - 1},
			},
		},
		{
			size: 384 * k,
			want: []chunkSize{
				{0, 128 * k},
				{128 * k, 256 * k},
			},
		},
		{
			size: 384*k + 1,
			want: []chunkSize{
				{0, 128 * k},
				{128 * k, 256 * k},
				{384 * k, 1},
			},
		},
		{
			size: 5 * k * k,
			want: []chunkSize{
				{0, 128 * k},
				{128 * k, 256 * k},
				{384 * k, 384 * k},
				{768 * k, 512 * k},
				{1280 * k, 640 * k},
				{1920 * k, 768 * k},
				{2688 * k, 896 * k},
				{3584 * k, 1024 * k},
				{4608 * k, 512 * k},
			},
		},
		{
			size: 10 * k * k,
			want: []chunkSize{
				{0, 128 * k},
				{128 * k, 256 * k},
				{384 * k, 384 * k},
				{768 * k, 512 * k},
				{1280 * k, 640 * k},
				{1920 * k, 768 * k},
				{2688 * k, 896 * k},
				{3584 * k, 1024 * k},
				{4608 * k, 1024 * k},
				{5632 * k, 1024 * k},
				{6656 * k, 1024 * k},
				{7680 * k, 1024 * k},
				{8704 * k, 1024 * k},
				{9728 * k, 512 * k},
			},
		},
	} {
		got := getChunkSizes(test.size)
		if !reflect.DeepEqual(test.want, got) {
			t.Errorf("incorrect chunks for size %d: want %#v, got %#v", test.size, test.want, got)

		}
	}
}

// TestNewCTR checks the stream from newCTR at any offset matches a
// stream started earlier, including when the block counter carries
// into its high 32 bits
func TestNewCTR(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, base := range []int64{0, (1<<32 - 2) * 16} {
		want := make([]byte, 1000)
		newCTR(block, nonce, base).XORKeyStream(want, want)
		for _, offset := range []int64{0, 1, 15, 16, 17, 500} {
			got := make([]byte, len(want)-int(offset))
			newCTR(block, nonce, base+offset).XORKeyStream(got, got)
			if !bytes.Equal(got, want[offset:]) {
				t.Errorf("base %d offset %d: wrong key stream", base, offset)
			}
		}
	}
	// the first block must use the nonce and a zero counter
	want := make([]byte, 16)
	cipher.NewCTR(block, append(nonce[:8:8], make([]byte, 8)...)).XORKeyStream(want, want)
	got := make([]byte, 16)
	newCTR(block, nonce, 0).XORKeyStream(got, got)
	if !bytes.Equal(got, want) {
		t.Error("wrong initial counter")
	}
}

// TestChunkMAC checks chunkMAC zero pads the last block
func TestChunkMAC(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	iv := make([]byte, 16)
	padded := make([]byte, 32)
	padded[0], padded[16] = 1, 2
	want := make([]byte, 32)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(want, padded)
	if got := chunkMAC(block, iv, padded[:17]); !bytes.Equal(got, want[16:]) {
		t.Errorf("padded chunk MAC %x, want %x", got, want[16:])
	}
}

// TestWithRetries checks withRetries retries until success, gives up
// at once on EOVERQUOTA and stops promptly when the context is cancelled
func TestWithRetries(t *testing.T) {
	m := New()
	m.SetRetries(10)
	calls := 0
	err := m.withRetries(context.Background(), "test", func() error {
		calls++
		if calls < 3 {
			return errors.New("fail")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Errorf("got err %v after %d calls, want success after 3", err, calls)
	}

	calls = 0
	err = m.withRetries(context.Background(), "test", func() error {
		calls++
		return EOVERQUOTA
	})
	if err != EOVERQUOTA || calls != 1 {
		t.Errorf("got err %v after %d calls, want EOVERQUOTA after 1", err, calls)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = m.withRetries(ctx, "test", func() error { return errors.New("fail") })
	if err == nil {
		t.Error("expected an error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v to stop after cancel", elapsed)
	}
}

// TestMACWriter checks macWriter against computing each chunk MAC in
// one go, for various start offsets and write sizes
func TestMACWriter(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	plain := make([]byte, 5*1024*1024+12345)
	for i := range plain {
		plain[i] = byte(i * 7)
	}
	chunks := getChunkSizes(int64(len(plain)))
	want := make([][]byte, len(chunks))
	for id, c := range chunks {
		data := paddnull(append([]byte(nil), plain[c.position:c.position+int64(c.size)]...), 16)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
		want[id] = data[len(data)-16:]
	}
	for _, offset := range []int64{0, 1, 131072, 300000} {
		for _, wsize := range []int{7, 4097, 1 << 20} {
			got := make([][]byte, len(chunks))
			w := newMACWriter(block, iv, chunks, offset, func(id int, mac []byte) { got[id] = mac })
			for p := plain[offset:]; len(p) > 0; {
				k := min(len(p), wsize)
				_, _ = w.Write(p[:k])
				p = p[k:]
			}
			for id, c := range chunks {
				if c.position < offset {
					if got[id] != nil {
						t.Errorf("offset %d: chunk %d MAC set for partial chunk", offset, id)
					}
				} else if !bytes.Equal(got[id], want[id]) {
					t.Errorf("offset %d write %d: chunk %d MAC wrong", offset, wsize, id)
				}
			}
		}
	}
}

func TestGroupChunks(t *testing.T) {
	const k = 1024
	chunks := getChunkSizes(7 * 1024 * k)
	for _, test := range []struct {
		size int64
		want []int // part sizes in k
	}{
		{size: 0, want: []int{128, 256, 384, 512, 640, 768, 896, 1024, 1024, 1024, 512}},
		{size: 1000 * k, want: []int{1280, 1408, 1920, 1024, 1024, 512}},
		{size: 3 * 1024 * k, want: []int{3584, 3072, 512}},
		{size: 100 * 1024 * k, want: []int{7 * 1024}},
	} {
		var got []int
		pos := int64(0)
		for _, p := range groupChunks(chunks, test.size) {
			if p.position != pos {
				t.Errorf("size %d: part at %d, want %d", test.size, p.position, pos)
			}
			pos += int64(p.size)
			got = append(got, p.size/k)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("size %d: got parts %v, want %v", test.size, got, test.want)
		}
	}
}
