package mega

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Default settings
const (
	API_URL                    = "https://g.api.mega.co.nz"
	BASE_DOWNLOAD_URL          = "https://mega.co.nz"
	RETRIES                    = 10
	DOWNLOAD_WORKERS           = 3
	MAX_DOWNLOAD_WORKERS       = 30
	UPLOAD_WORKERS             = 1
	MAX_UPLOAD_WORKERS         = 30
	TIMEOUT                    = time.Second * 10
	HTTPSONLY                  = false
	minSleepTime               = 10 * time.Millisecond // for retries
	maxSleepTime               = 5 * time.Second       // for retries
	X_MEGA_USER_AGENT          = ""                    // custom user agent string. Not set if empty
	HASHCASH_CHALLENGE_TIMEOUT = time.Minute * 5       // time limit to solve hashcash challenge
)

type config struct {
	baseurl    string
	retries    int
	dl_workers int
	ul_workers int
	timeout    time.Duration
	https      bool
}

func newConfig() config {
	return config{
		baseurl:    getAPIBaseURL(),
		retries:    RETRIES,
		dl_workers: DOWNLOAD_WORKERS,
		ul_workers: UPLOAD_WORKERS,
		timeout:    TIMEOUT,
		https:      HTTPSONLY,
	}
}

// Set mega service base url
func (c *config) SetAPIUrl(u string) {
	if strings.HasSuffix(u, "/") {
		u = strings.TrimRight(u, "/")
	}
	c.baseurl = u
}

// Set number of retries for api calls
func (c *config) SetRetries(r int) {
	c.retries = r
}

// Set concurrent download workers
func (c *config) SetDownloadWorkers(w int) error {
	if w <= MAX_DOWNLOAD_WORKERS {
		c.dl_workers = w
		return nil
	}

	return EWORKER_LIMIT_EXCEEDED
}

// Set connection timeout
func (c *config) SetTimeOut(t time.Duration) {
	c.timeout = t
}

// Set concurrent upload workers
func (c *config) SetUploadWorkers(w int) error {
	if w <= MAX_UPLOAD_WORKERS {
		c.ul_workers = w
		return nil
	}

	return EWORKER_LIMIT_EXCEEDED
}

// Set use https for transfers
func (c *config) SetHTTPS(e bool) {
	c.https = e
}

type Mega struct {
	config
	// Version of the account
	accountVersion int
	// Salt for the account if accountVersion > 1
	accountSalt []byte
	// Sequence number
	sn int64
	// Server state sn
	ssn string
	// Session ID
	sid string
	// Master key
	k []byte
	// User handle
	uh []byte
	// Filesystem object
	FS *MegaFS
	// HTTP Client
	client *http.Client
	// Loggers
	logf   func(format string, v ...any)
	debugf func(format string, v ...any)
	// serialize the API requests
	apiMu sync.Mutex
	// mutex to protext waitEvents
	waitEventsMu sync.Mutex
	// Outstanding channels to close to indicate events all received
	waitEvents []chan struct{}
}

// Filesystem node types
const (
	FILE   = 0
	FOLDER = 1
	ROOT   = 2
	INBOX  = 3
	TRASH  = 4
)

// Filesystem node
type Node struct {
	fs       *MegaFS
	name     string
	hash     string
	parent   *Node
	children []*Node
	ntype    int
	size     int64
	ts       time.Time
	meta     NodeMeta
}

func (n *Node) removeChild(c *Node) bool {
	index := -1
	for i, v := range n.children {
		if v.hash == c.hash {
			index = i
			break
		}
	}

	if index >= 0 {
		n.children[index] = n.children[len(n.children)-1]
		n.children = n.children[:len(n.children)-1]
		return true
	}

	return false
}

func (n *Node) addChild(c *Node) {
	if n != nil {
		n.children = append(n.children, c)
	}
}

func (n *Node) getChildren() []*Node {
	return n.children
}

func (n *Node) GetType() int {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.ntype
}

func (n *Node) GetSize() int64 {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.size
}

func (n *Node) GetTimeStamp() time.Time {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.ts
}

func (n *Node) GetName() string {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.name
}

func (n *Node) GetHash() string {
	n.fs.mutex.Lock()
	defer n.fs.mutex.Unlock()
	return n.hash
}

type NodeMeta struct {
	key     []byte
	compkey []byte
	iv      []byte
	mac     []byte
}

// Mega filesystem object
type MegaFS struct {
	root   *Node
	trash  *Node
	inbox  *Node
	sroots []*Node
	lookup map[string]*Node
	skmap  map[string]string
	mutex  sync.Mutex
}

// Get filesystem root node
func (fs *MegaFS) GetRoot() *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.root
}

// Get filesystem trash node
func (fs *MegaFS) GetTrash() *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.trash
}

// Get inbox node
func (fs *MegaFS) GetInbox() *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.inbox
}

// Get a node pointer from its hash
func (fs *MegaFS) HashLookup(h string) *Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	return fs.hashLookup(h)
}

func (fs *MegaFS) hashLookup(h string) *Node {
	if node, ok := fs.lookup[h]; ok {
		return node
	}

	return nil
}

// Get the list of child nodes for a given node
func (fs *MegaFS) GetChildren(n *Node) ([]*Node, error) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	var empty []*Node

	if n == nil {
		return empty, EARGS
	}

	node := fs.hashLookup(n.hash)
	if node == nil {
		return empty, ENOENT
	}

	return node.getChildren(), nil
}

// Retrieve all the nodes in the given node tree path by name
// This method returns array of nodes upto the matched subpath
// (in same order as input names array) even if the target node is not located.
func (fs *MegaFS) PathLookup(root *Node, ns []string) ([]*Node, error) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	if root == nil {
		return nil, EARGS
	}

	var err error
	var found = true

	nodepath := []*Node{}

	children := root.children
	for _, name := range ns {
		found = false
		for _, n := range children {
			if n.name == name {
				nodepath = append(nodepath, n)
				children = n.children
				found = true
				break
			}
		}

		if !found {
			break
		}
	}

	if !found {
		err = ENOENT
	}

	return nodepath, err
}

// Get top level directory nodes shared by other users
func (fs *MegaFS) GetSharedRoots() []*Node {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.sroots
}

func newMegaFS() *MegaFS {
	fs := &MegaFS{
		lookup: make(map[string]*Node),
		skmap:  make(map[string]string),
	}
	return fs
}

func New() *Mega {
	max := big.NewInt(0x100000000)
	bigx, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err) // this should be returned, but this is a public interface
	}
	cfg := newConfig()
	mgfs := newMegaFS()
	m := &Mega{
		config: cfg,
		sn:     bigx.Int64(),
		FS:     mgfs,
		client: newHttpClient(cfg.timeout),
	}
	m.SetLogger(log.Printf)
	m.SetDebugger(nil)
	return m
}

// SetClient sets the HTTP client in use
func (m *Mega) SetClient(client *http.Client) *Mega {
	m.client = client
	return m
}

// discardLogf discards the log messages
func discardLogf(format string, v ...any) {
}

// Returns an opaque string representing the session
func (m *Mega) GetSessionID() string {
	return m.sid
}

func (m *Mega) GetMasterKey() []byte {
	return m.k
}

// "Login" using the session ID (for API auth) and master key (for decryption). Alternative to logging in with username/password
// This can be used to import back a session exported with GetSessionID and GetMasterKey without requiring the password again
func (m *Mega) LoginWithKeys(sessionId string, masterKey []byte) error {
	m.sid = sessionId
	m.k = masterKey
	return m.postAuthInit()
}

// SetLogger sets the logger for important messages.  By default this
// is log.Printf.  Use nil to discard the messages.
func (m *Mega) SetLogger(logf func(format string, v ...any)) *Mega {
	if logf == nil {
		logf = discardLogf
	}
	m.logf = logf
	return m
}

// SetDebugger sets the logger for debug messages.  By default these
// messages are not output.
func (m *Mega) SetDebugger(debugf func(format string, v ...any)) *Mega {
	if debugf == nil {
		debugf = discardLogf
	}
	m.debugf = debugf
	return m
}

// backOffSleep sleeps for the time pointed to then adjusts it by
// doubling it up to a maximum of maxSleepTime.
//
// This produces a truncated exponential backoff sleep
func backOffSleep(pt *time.Duration) {
	time.Sleep(*pt)
	*pt *= 2
	if *pt > maxSleepTime {
		*pt = maxSleepTime
	}
}

// API request method
func (m *Mega) api_request(r []byte) (buf []byte, err error) {
	var resp *http.Response
	// serialize the API requests
	m.apiMu.Lock()
	defer func() {
		m.sn++
		m.apiMu.Unlock()
	}()

	url := fmt.Sprintf("%s/cs?id=%d", m.baseurl, m.sn)

	if m.sid != "" {
		url = fmt.Sprintf("%s&sid=%s", url, m.sid)
	}

	sleepTime := minSleepTime // initial backoff time
	for i := 0; i < m.retries+1; i++ {
		if i != 0 {
			m.debugf("Retry API request %d/%d: %v", i, m.retries, err)
			backOffSleep(&sleepTime)
		}

		// Create request
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(r))
		if err != nil {
			continue
		}
		addRequestHeaders(req)

		// Send request
		resp, err = m.client.Do(req)
		if err != nil {
			continue
		}

		// Handle 402 Payment Required status with hashcash challenge
		if resp.StatusCode == 402 {
			sleepTime = minSleepTime // reset exp backoff time
			hashCashHeader := resp.Header.Get("X-Hashcash")
			if hashCashHeader == "" {
				_ = resp.Body.Close()
				continue
			}

			// Parse hashcash header
			easiness, token, valid := parseHashcash(hashCashHeader)
			if !valid {
				_ = resp.Body.Close()
				continue
			}

			// Close the current response before making a new request
			_ = resp.Body.Close()

			// Generate hashcash response
			cashValue, err := solveHashCashChallenge(token, easiness, HASHCASH_CHALLENGE_TIMEOUT, halfCPUCores())
			if err != nil {
				m.debugf("Failed to solve hashcash challenge: %v", err)
				continue
			}
			if cashValue == "" {
				m.debugf("Failed to solve hashcash challenge: empty cash value")
				continue
			}

			// Create a new request with the hashcash header
			req, err = http.NewRequest("POST", url, bytes.NewBuffer(r))
			if err != nil {
				continue
			}
			addHashCashRequestHeaders(req, token, cashValue)
			// Send the new request
			resp, err = m.client.Do(req)
			if err != nil {
				continue
			}

			// If still getting 402, give up this attempt and retry
			if resp.StatusCode == 402 {
				_ = resp.Body.Close()
				continue
			}
		}

		if resp.StatusCode != 200 {
			// err must be not-nil on a continue
			_ = resp.Body.Close()
			continue
		}

		buf, err = io.ReadAll(resp.Body)
		if err != nil {
			_ = resp.Body.Close()
			continue
		}
		err = resp.Body.Close()
		if err != nil {
			continue
		}

		// at this point the body is read and closed

		if !bytes.HasPrefix(buf, []byte("[")) && !bytes.HasPrefix(buf, []byte("-")) {
			return nil, EBADRESP
		}

		if len(buf) < 6 {
			var emsg [1]ErrorMsg
			err = json.Unmarshal(buf, &emsg)
			if err != nil {
				err = json.Unmarshal(buf, &emsg[0])
			}
			if err != nil {
				return buf, EBADRESP
			}
			err = parseError(emsg[0])
			if err == EAGAIN {
				continue
			}
			return buf, err
		}

		if err == nil {
			return buf, nil
		}
	}

	return nil, err
}

// prelogin call
func (m *Mega) prelogin(email string) error {
	var msg [1]PreloginMsg
	var res [1]PreloginResp

	email = strings.ToLower(email) // mega uses lowercased emails for login purposes - FIXME is this true for prelogin?

	msg[0].Cmd = "us0"
	msg[0].User = email

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	result, err := m.api_request(req)
	if err != nil {
		return err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return err
	}

	if res[0].Version == 0 {
		return errors.New("prelogin: no version returned")
	} else if res[0].Version > 2 {
		return fmt.Errorf("prelogin: version %d account not supported", res[0].Version)
	} else if res[0].Version == 2 {
		if len(res[0].Salt) == 0 {
			return errors.New("prelogin: no salt returned")
		}
		m.accountSalt, err = base64urldecode(res[0].Salt)
		if err != nil {
			return err
		}
	}
	m.accountVersion = res[0].Version

	return nil
}

// Authenticate and start a session
func (m *Mega) login(email string, passwd string, multiFactor string) error {
	var msg [1]LoginMsg
	var res [1]LoginResp
	var err error
	var result []byte

	email = strings.ToLower(email) // mega uses lowercased emails for login purposes

	passkey, err := password_key(passwd)
	if err != nil {
		return err
	}
	uhandle, err := stringhash(email, passkey)
	if err != nil {
		return err
	}
	m.uh = make([]byte, len(uhandle))
	copy(m.uh, uhandle)

	msg[0].Cmd = "us"
	msg[0].User = email
	msg[0].Mfa = multiFactor

	if m.accountVersion == 1 {
		msg[0].Handle = uhandle
	} else {
		const derivedKeyLength = 2 * aes.BlockSize
		derivedKey := pbkdf2.Key([]byte(passwd), m.accountSalt, 100000, derivedKeyLength, sha512.New)
		authKey := derivedKey[aes.BlockSize:]
		passkey = derivedKey[:aes.BlockSize]

		sessionKey := make([]byte, aes.BlockSize)
		_, err = rand.Read(sessionKey)
		if err != nil {
			return err
		}
		msg[0].Handle = base64urlencode(authKey)
		msg[0].SessionKey = base64urlencode(sessionKey)
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	result, err = m.api_request(req)
	if err != nil {
		return err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return err
	}

	m.k, err = base64urldecode(res[0].Key)
	if err != nil {
		return err
	}
	cipher, err := aes.NewCipher(passkey)
	if err != nil {
		return err
	}
	cipher.Decrypt(m.k, m.k)
	m.sid, err = decryptSessionId(res[0].Privk, res[0].Csid, m.k)
	if err != nil {
		return err
	}
	return nil
}

// Authenticate and start a session
func (m *Mega) Login(email string, passwd string) error {
	return m.MultiFactorLogin(email, passwd, "")
}

// MultiFactorLogin - Authenticate and start a session with 2FA
func (m *Mega) MultiFactorLogin(email, passwd, multiFactor string) error {
	err := m.prelogin(email)
	if err != nil {
		return err
	}

	err = m.login(email, passwd, multiFactor)
	if err != nil {
		return err
	}

	return m.postAuthInit()
}

// Finish initializing the Mega client after Login*()
func (m *Mega) postAuthInit() error {

	waitEvent := m.WaitEventsStart()

	err := m.getFileSystem()
	if err != nil {
		return err
	}

	// Wait until the all the pending events have been received
	m.WaitEvents(waitEvent, 5*time.Second)

	return nil
}

// WaitEventsStart - call this before you do the action which might
// generate events then use the returned channel as a parameter to
// WaitEvents to wait for the event(s) to be received.
func (m *Mega) WaitEventsStart() <-chan struct{} {
	ch := make(chan struct{})
	m.waitEventsMu.Lock()
	m.waitEvents = append(m.waitEvents, ch)
	m.waitEventsMu.Unlock()
	return ch
}

// WaitEvents waits for all outstanding events to be received for a
// maximum of duration.  eventChan should be a channel as returned
// from WaitEventStart.
//
// If the timeout elapsed then it returns true otherwise false.
func (m *Mega) WaitEvents(eventChan <-chan struct{}, duration time.Duration) (timedout bool) {
	m.debugf("Waiting for events to be finished for %v", duration)
	timer := time.NewTimer(duration)
	select {
	case <-eventChan:
		m.debugf("Events received")
		timedout = false
	case <-timer.C:
		m.debugf("Timeout waiting for events")
		timedout = true
	}
	timer.Stop()
	return timedout
}

// waitEventsFire - fire the wait event
func (m *Mega) waitEventsFire() {
	m.waitEventsMu.Lock()
	if len(m.waitEvents) > 0 {
		m.debugf("Signalling events received")
		for _, ch := range m.waitEvents {
			close(ch)
		}
		m.waitEvents = nil
	}
	m.waitEventsMu.Unlock()
}

// Get user information
func (m *Mega) GetUser() (UserResp, error) {
	var msg [1]UserMsg
	var res [1]UserResp

	msg[0].Cmd = "ug"

	req, err := json.Marshal(msg)
	if err != nil {
		return res[0], err
	}
	result, err := m.api_request(req)
	if err != nil {
		return res[0], err
	}

	err = json.Unmarshal(result, &res)
	return res[0], err
}

// Get quota information
func (m *Mega) GetQuota() (QuotaResp, error) {
	var msg [1]QuotaMsg
	var res [1]QuotaResp

	msg[0].Cmd = "uq"
	msg[0].Xfer = 1
	msg[0].Strg = 1

	req, err := json.Marshal(msg)
	if err != nil {
		return res[0], err
	}
	result, err := m.api_request(req)
	if err != nil {
		return res[0], err
	}

	err = json.Unmarshal(result, &res)
	return res[0], err
}

// Add a node into filesystem
func (m *Mega) addFSNode(itm FSNode) (*Node, error) {
	var compkey, key []uint32
	var attr FileAttr
	var node, parent *Node
	var err error

	master_aes, err := aes.NewCipher(m.k)
	if err != nil {
		return nil, err
	}

	switch {
	case itm.T == FOLDER || itm.T == FILE:
		args := strings.Split(itm.Key, ":")
		if len(args) < 2 {
			return nil, fmt.Errorf("not enough : in item.Key: %q", itm.Key)
		}
		itemUser, itemKey := args[0], args[1]
		itemKeyParts := strings.Split(itemKey, "/")
		if len(itemKeyParts) >= 2 {
			itemKey = itemKeyParts[0]
			// the other part is maybe a share key handle?
		}

		switch {
		// File or folder owned by current user
		case itemUser == itm.User:
			buf, err := base64urldecode(itemKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(master_aes, buf, buf)
			if err != nil {
				return nil, err
			}
			compkey, err = bytes_to_a32(buf)
			if err != nil {
				return nil, err
			}
			// Shared folder
		case itm.SUser != "" && itm.SKey != "":
			sk, err := base64urldecode(itm.SKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(master_aes, sk, sk)
			if err != nil {
				return nil, err
			}
			sk_aes, err := aes.NewCipher(sk)
			if err != nil {
				return nil, err
			}

			m.FS.skmap[itm.Hash] = itm.SKey
			buf, err := base64urldecode(itemKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(sk_aes, buf, buf)
			if err != nil {
				return nil, err
			}
			compkey, err = bytes_to_a32(buf)
			if err != nil {
				return nil, err
			}
			// Shared file
		default:
			k, ok := m.FS.skmap[itemUser]
			if !ok {
				return nil, errors.New("couldn't find decryption key for shared file")
			}
			b, err := base64urldecode(k)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(master_aes, b, b)
			if err != nil {
				return nil, err
			}
			block, err := aes.NewCipher(b)
			if err != nil {
				return nil, err
			}
			buf, err := base64urldecode(itemKey)
			if err != nil {
				return nil, err
			}
			err = blockDecrypt(block, buf, buf)
			if err != nil {
				return nil, err
			}
			compkey, err = bytes_to_a32(buf)
			if err != nil {
				return nil, err
			}
		}

		switch {
		case itm.T == FILE:
			if len(compkey) < 8 {
				m.logf("ignoring item: compkey too short (%d): %#v", len(compkey), itm)
				return nil, nil
			}
			key = []uint32{compkey[0] ^ compkey[4], compkey[1] ^ compkey[5], compkey[2] ^ compkey[6], compkey[3] ^ compkey[7]}
		default:
			key = compkey
		}

		bkey, err := a32_to_bytes(key)
		if err != nil {
			// FIXME:
			attr.Name = "BAD ATTRIBUTE"
		} else {
			attr, err = decryptAttr(bkey, itm.Attr)
			// FIXME:
			if err != nil {
				attr.Name = "BAD ATTRIBUTE"
			}
		}
	}

	n, ok := m.FS.lookup[itm.Hash]
	switch {
	case ok:
		node = n
	default:
		node = &Node{
			fs:    m.FS,
			ntype: itm.T,
			size:  itm.Sz,
			ts:    time.Unix(itm.Ts, 0),
		}

		m.FS.lookup[itm.Hash] = node
	}

	n, ok = m.FS.lookup[itm.Parent]
	switch {
	case ok:
		parent = n
		// Detach the node from its old parent if it is being
		// reparented so it doesn't appear in two directories.
		if node.parent != nil && node.parent != parent {
			node.parent.removeChild(node)
		}
		parent.removeChild(node)
		parent.addChild(node)
	default:
		parent = nil
		if itm.Parent != "" {
			parent = &Node{
				fs:       m.FS,
				children: []*Node{node},
				ntype:    FOLDER,
			}
			m.FS.lookup[itm.Parent] = parent
		}
	}

	switch {
	case itm.T == FILE:
		var meta NodeMeta
		meta.key, err = a32_to_bytes(key)
		if err != nil {
			return nil, err
		}
		meta.iv, err = a32_to_bytes([]uint32{compkey[4], compkey[5], 0, 0})
		if err != nil {
			return nil, err
		}
		meta.mac, err = a32_to_bytes([]uint32{compkey[6], compkey[7]})
		if err != nil {
			return nil, err
		}
		meta.compkey, err = a32_to_bytes(compkey)
		if err != nil {
			return nil, err
		}
		node.meta = meta
	case itm.T == FOLDER:
		var meta NodeMeta
		meta.key, err = a32_to_bytes(key)
		if err != nil {
			return nil, err
		}
		meta.compkey, err = a32_to_bytes(compkey)
		if err != nil {
			return nil, err
		}
		node.meta = meta
	case itm.T == ROOT:
		attr.Name = "Cloud Drive"
		m.FS.root = node
	case itm.T == INBOX:
		attr.Name = "InBox"
		m.FS.inbox = node
	case itm.T == TRASH:
		attr.Name = "Trash"
		m.FS.trash = node
	}

	// Shared directories
	if itm.SUser != "" && itm.SKey != "" {
		m.FS.sroots = append(m.FS.sroots, node)
	}

	node.name = attr.Name
	node.hash = itm.Hash
	node.parent = parent
	node.ntype = itm.T

	return node, nil
}

// Get all nodes from filesystem
func (m *Mega) getFileSystem() error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var msg [1]FilesMsg
	var res [1]FilesResp

	msg[0].Cmd = "f"
	msg[0].C = 1

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	result, err := m.api_request(req)
	if err != nil {
		return err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return err
	}

	for _, sk := range res[0].Ok {
		m.FS.skmap[sk.Hash] = sk.Key
	}

	for _, itm := range res[0].F {
		_, err = m.addFSNode(itm)
		if err != nil {
			m.debugf("couldn't decode FSNode %#v: %v ", itm, err)
			continue
		}
	}

	m.ssn = res[0].Sn

	go m.pollEvents()

	return nil
}

// Move a file from one location to another
func (m *Mega) Move(src *Node, parent *Node) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	if src == nil || parent == nil {
		return EARGS
	}
	var msg [1]MoveFileMsg
	var err error

	msg[0].Cmd = "m"
	msg[0].N = src.hash
	msg[0].T = parent.hash
	msg[0].I, err = randString(10)
	if err != nil {
		return err
	}

	request, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = m.api_request(request)
	if err != nil {
		return err
	}

	if src.parent != nil {
		src.parent.removeChild(src)
	}

	parent.addChild(src)
	src.parent = parent

	return nil
}

// Rename a file or folder
func (m *Mega) Rename(src *Node, name string) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	if src == nil {
		return EARGS
	}
	var msg [1]FileAttrMsg

	master_aes, err := aes.NewCipher(m.k)
	if err != nil {
		return err
	}
	attr := FileAttr{name}
	attr_data, err := encryptAttr(src.meta.key, attr)
	if err != nil {
		return err
	}
	key := make([]byte, len(src.meta.compkey))
	err = blockEncrypt(master_aes, key, src.meta.compkey)
	if err != nil {
		return err
	}

	msg[0].Cmd = "a"
	msg[0].Attr = attr_data
	msg[0].Key = base64urlencode(key)
	msg[0].N = src.hash
	msg[0].I, err = randString(10)
	if err != nil {
		return err
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = m.api_request(req)
	if err != nil {
		return err
	}

	src.name = name

	return nil
}

// Create a directory in the filesystem
func (m *Mega) CreateDir(name string, parent *Node) (*Node, error) {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	if parent == nil {
		return nil, EARGS
	}
	var msg [1]UploadCompleteMsg
	var res [1]UploadCompleteResp

	compkey := []uint32{0, 0, 0, 0, 0, 0}
	for i := range compkey {
		compkey[i] = uint32(mrand.Int31())
	}

	master_aes, err := aes.NewCipher(m.k)
	if err != nil {
		return nil, err
	}
	attr := FileAttr{name}
	ukey, err := a32_to_bytes(compkey[:4])
	if err != nil {
		return nil, err
	}
	attr_data, err := encryptAttr(ukey, attr)
	if err != nil {
		return nil, err
	}
	key := make([]byte, len(ukey))
	err = blockEncrypt(master_aes, key, ukey)
	if err != nil {
		return nil, err
	}

	msg[0].Cmd = "p"
	msg[0].T = parent.hash
	msg[0].N[0].H = "xxxxxxxx"
	msg[0].N[0].T = FOLDER
	msg[0].N[0].A = attr_data
	msg[0].N[0].K = base64urlencode(key)
	msg[0].I, err = randString(10)
	if err != nil {
		return nil, err
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	result, err := m.api_request(req)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return nil, err
	}
	node, err := m.addFSNode(res[0].F[0])

	return node, err
}

// Delete a file or directory from filesystem
func (m *Mega) Delete(node *Node, destroy bool) error {
	if node == nil {
		return EARGS
	}
	if !destroy {
		return m.Move(node, m.FS.trash)
	}

	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var msg [1]FileDeleteMsg
	var err error
	msg[0].Cmd = "d"
	msg[0].N = node.hash
	msg[0].I, err = randString(10)
	if err != nil {
		return err
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = m.api_request(req)
	if err != nil {
		return err
	}

	if node.parent != nil {
		node.parent.removeChild(node)
	}
	delete(m.FS.lookup, node.hash)

	return nil
}

// process an add node event
func (m *Mega) processAddNode(evRaw []byte) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var ev FSEvent
	err := json.Unmarshal(evRaw, &ev)
	if err != nil {
		return err
	}

	for _, itm := range ev.T.Files {
		_, err = m.addFSNode(itm)
		if err != nil {
			return err
		}
	}
	return nil
}

// process an update node event
func (m *Mega) processUpdateNode(evRaw []byte) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var ev FSEvent
	err := json.Unmarshal(evRaw, &ev)
	if err != nil {
		return err
	}

	node := m.FS.hashLookup(ev.N)
	if node == nil {
		return ENOENT
	}
	attr, err := decryptAttr(node.meta.key, ev.Attr)
	if err == nil {
		node.name = attr.Name
	} else {
		node.name = "BAD ATTRIBUTE"
	}

	node.ts = time.Unix(ev.Ts, 0)
	return nil
}

// process a delete node event
func (m *Mega) processDeleteNode(evRaw []byte) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var ev FSEvent
	err := json.Unmarshal(evRaw, &ev)
	if err != nil {
		return err
	}

	node := m.FS.hashLookup(ev.N)
	if node != nil && node.parent != nil {
		node.parent.removeChild(node)
		// A delete event which is part of a move (m is set) will be
		// followed by an add node event re-attaching the node, so keep
		// it in the lookup map to preserve the node's identity.
		if ev.Moved == 0 {
			delete(m.FS.lookup, node.hash)
		}
	}
	return nil
}

// Listen for server event notifications and play actions
func (m *Mega) pollEvents() {
	var err error
	var resp *http.Response
	sleepTime := minSleepTime // initial backoff time
	for {
		if err != nil {
			m.debugf("pollEvents: error from server", err)
			backOffSleep(&sleepTime)
		} else {
			// reset sleep time to minimum on success
			sleepTime = minSleepTime
		}

		url := fmt.Sprintf("%s/sc?sn=%s&sid=%s", m.baseurl, m.ssn, m.sid)
		resp, err = m.client.Post(url, "application/xml", nil)
		if err != nil {
			m.logf("pollEvents: Error fetching status: %s", err)
			continue
		}

		if resp.StatusCode != 200 {
			m.logf("pollEvents: Error from server: %s", resp.Status)
			_ = resp.Body.Close()
			continue
		}

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			m.logf("pollEvents: Error reading body: %v", err)
			_ = resp.Body.Close()
			continue
		}
		err = resp.Body.Close()
		if err != nil {
			m.logf("pollEvents: Error closing body: %v", err)
			continue
		}

		// body is read and closed here

		// First attempt to parse an array
		var events Events
		err = json.Unmarshal(buf, &events)
		if err != nil {
			// Try parsing as a lone error message
			var emsg ErrorMsg
			err = json.Unmarshal(buf, &emsg)
			if err != nil {
				m.logf("pollEvents: Bad response received from server: %s", buf)
			} else {
				err = parseError(emsg)
				if err == EAGAIN {
				} else if err != nil {
					m.logf("pollEvents: Error received from server: %v", err)
				}
			}
			continue
		}

		// if wait URL is set, then fetch it and continue - we
		// don't expect anything else if we have a wait URL.
		if events.W != "" {
			m.waitEventsFire()
			if len(events.E) > 0 {
				m.logf("pollEvents: Unexpected event with w set: %s", buf)
			}
			resp, err = m.client.Get(events.W)
			if err == nil {
				_ = resp.Body.Close()
			}
			continue
		}
		m.ssn = events.Sn

		// For each event in the array, parse it
		for _, evRaw := range events.E {
			// First attempt to unmarshal as an error message
			var emsg ErrorMsg
			err = json.Unmarshal(evRaw, &emsg)
			if err == nil {
				m.logf("pollEvents: Error message received %s", evRaw)
				err = parseError(emsg)
				if err != nil {
					m.logf("pollEvents: Event from server was error: %v", err)
				}
				continue
			}

			// Now unmarshal as a generic event
			var gev GenericEvent
			err = json.Unmarshal(evRaw, &gev)
			if err != nil {
				m.logf("pollEvents: Couldn't parse event from server: %v: %s", err, evRaw)
				continue
			}
			m.debugf("pollEvents: Parsing event %q: %s", gev.Cmd, evRaw)

			// Work out what to do with the event
			var process func([]byte) error
			switch gev.Cmd {
			case "t": // node addition
				process = m.processAddNode
			case "u": // node update
				process = m.processUpdateNode
			case "d": // node deletion
				process = m.processDeleteNode
			case "s", "s2": // share addition/update/revocation
			case "c": // contact addition/update
			case "k": // crypto key request
			case "fa": // file attribute update
			case "ua": // user attribute update
			case "psts": // account updated
			case "ipc": // incoming pending contact request (to us)
			case "opc": // outgoing pending contact request (from us)
			case "upci": // incoming pending contact request update (accept/deny/ignore)
			case "upco": // outgoing pending contact request update (from them, accept/deny/ignore)
			case "ph": // public links handles
			case "se": // set email
			case "mcc": // chat creation / peer's invitation / peer's removal
			case "mcna": // granted / revoked access to a node
			case "uac": // user access control
			default:
				m.debugf("pollEvents: Unknown message %q received: %s", gev.Cmd, evRaw)
			}

			// process the event if we can
			if process != nil {
				err := process(evRaw)
				if err != nil {
					m.logf("pollEvents: Error processing event %q '%s': %v", gev.Cmd, evRaw, err)
				}
			}
		}
	}
}

func (m *Mega) getLink(n *Node) (string, error) {
	var msg [1]GetLinkMsg
	var res [1]string

	msg[0].Cmd = "l"
	msg[0].N = n.GetHash()

	req, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	result, err := m.api_request(req)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(result, &res)
	if err != nil {
		return "", err
	}
	return res[0], nil
}

// Exports public link for node, with or without decryption key included
func (m *Mega) Link(n *Node, includeKey bool) (string, error) {
	id, err := m.getLink(n)
	if err != nil {
		return "", err
	}
	if includeKey {
		m.FS.mutex.Lock()
		key := base64urlencode(n.meta.compkey)
		m.FS.mutex.Unlock()
		return fmt.Sprintf("%v/#!%v!%v", BASE_DOWNLOAD_URL, id, key), nil
	} else {
		return fmt.Sprintf("%v/#!%v", BASE_DOWNLOAD_URL, id), nil
	}
}

// addRequestHeaders adds standard headers to a request
func addRequestHeaders(req *http.Request) {
	userAgent := os.Getenv("X_MEGA_USER_AGENT")
	if userAgent != "" || X_MEGA_USER_AGENT != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	req.Header.Set("Content-Type", "application/json")
}

// addHashCashRequestHeaders adds standard headers and hashcash headers to a request
func addHashCashRequestHeaders(req *http.Request, token string, cashValue string) {
	addRequestHeaders(req)
	if token != "" && cashValue != "" {
		req.Header.Set("X-Hashcash", fmt.Sprintf("1:%s:%s", token, cashValue))
	}
}

// getAPIBaseURL returns the base URL for API requests
func getAPIBaseURL() string {
	url := os.Getenv("X_MEGA_API_URL")
	if url == "" {
		return API_URL
	}
	return url
}
