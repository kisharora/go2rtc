package xiaomi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/internal/api"
	"github.com/AlexxIT/go2rtc/internal/app"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi/crypto"
	"github.com/rs/zerolog"
)

func Init() {
	var v struct {
		Cfg map[string]string `yaml:"xiaomi"`
	}
	app.LoadConfig(&v)

	tokens = v.Cfg

	log = app.GetLogger("xiaomi")

	streams.HandleFunc("xiaomi", func(rawURL string) (core.Producer, error) {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}

		if u.User != nil {
			rawURL, err = getCameraURL(u)
			if err != nil {
				return nil, err
			}
		}

		log.Debug().Msgf("xiaomi: dial %s", rawURL)

		return xiaomi.Dial(rawURL)
	})

	api.HandleFunc("api/xiaomi", apiXiaomi)
	api.HandleFunc("api/xiaomi/ctl", apiXiaomiCtl)

	// Learn every camera flip setting ahead of time (and every 6 h), so the
	// first move is one command, not a lookup plus a command.
	go func() {
		time.Sleep(5 * time.Second)
		for {
			for _, sources := range streams.GetAllSources() {
				for _, raw := range sources {
					if !strings.HasPrefix(raw, "xiaomi://") {
						continue
					}
					if u, err := url.Parse(raw); err == nil {
						refreshFlip(u.User, u.Query().Get("did"))
					}
				}
			}
			time.Sleep(6 * time.Hour)
		}
	}()
}

var log zerolog.Logger

var tokens map[string]string
var clouds map[string]*xiaomi.Cloud
var cloudsMu sync.Mutex

func getCloud(userID string) (*xiaomi.Cloud, error) {
	cloudsMu.Lock()
	defer cloudsMu.Unlock()

	if cloud := clouds[userID]; cloud != nil {
		return cloud, nil
	}

	cloud := xiaomi.NewCloud(AppXiaomiHome)
	if err := cloud.LoginWithToken(userID, tokens[userID]); err != nil {
		return nil, err
	}
	if clouds == nil {
		clouds = map[string]*xiaomi.Cloud{userID: cloud}
	} else {
		clouds[userID] = cloud
	}
	return cloud, nil
}

func cloudRequest(userID, region, apiURL, params string) ([]byte, error) {
	cloud, err := getCloud(userID)
	if err != nil {
		return nil, err
	}
	return cloud.Request(GetBaseURL(region), apiURL, params, nil)
}

func cloudUserRequest(user *url.Userinfo, apiURL, params string) ([]byte, error) {
	userID := user.Username()
	region, _ := user.Password()
	return cloudRequest(userID, region, apiURL, params)
}

func getCameraURL(url *url.URL) (string, error) {
	model := url.Query().Get("model")

	// It is not known which models need to be awakened.
	// Probably all the doorbells and all the battery cameras.
	if strings.Contains(model, ".cateye.") {
		_ = wakeUpCamera(url)
	}

	// The getMissURL request has a fallback to getP2PURL.
	// But for known models we can save one request to the cloud.
	if xiaomi.IsLegacy(model) {
		return getLegacyURL(url)
	}
	return getMissURL(url)
}

func getLegacyURL(url *url.URL) (string, error) {
	query := url.Query()

	clientPublic, clientPrivate, err := crypto.GenerateKey()
	if err != nil {
		return "", err
	}

	params := fmt.Sprintf(`{"did":"%s","toSignAppData":"%x"}`, query.Get("did"), clientPublic)

	userID := url.User.Username()
	region, _ := url.User.Password()
	res, err := cloudRequest(userID, region, "/device/devicepass", params)
	if err != nil {
		return "", err
	}

	var v struct {
		UID       string `json:"p2p_id"`
		Password  string `json:"password"`
		PublicKey string `json:"p2p_dev_public_key"`
		Sign      string `json:"signForAppData"`
	}
	if err = json.Unmarshal(res, &v); err != nil {
		return "", err
	}

	query.Set("uid", v.UID)

	if v.Sign != "" {
		query.Set("client_public", hex.EncodeToString(clientPublic))
		query.Set("client_private", hex.EncodeToString(clientPrivate))
		query.Set("device_public", v.PublicKey)
		query.Set("sign", v.Sign)
	} else {
		query.Set("password", v.Password)
	}

	url.RawQuery = query.Encode()
	return url.String(), nil
}

// cs2CloudRelayHost is the Mi-Cloud relay endpoint used by cs2 cameras
// that do not expose port 32108 on the LAN (e.g. xiaomi.camera.c302n).
// One of a small published pool of Alibaba Cloud addresses; a future
// improvement could derive the right one from the p2p_id region prefix.
const cs2CloudRelayHost = "47.236.156.107"

func getMissURL(url *url.URL) (string, error) {
	clientPublic, clientPrivate, err := crypto.GenerateKey()
	if err != nil {
		return "", err
	}

	query := url.Query()
	params := fmt.Sprintf(
		`{"app_pubkey":"%x","did":"%s","support_vendors":"TUTK_CS2_MTP"}`,
		clientPublic, query.Get("did"),
	)

	t0 := time.Now()
	res, err := cloudUserRequest(url.User, "/v2/device/miss_get_vendor", params)
	log.Info().Msgf("[xiaomi] vendor did=%s in %dms err=%v", query.Get("did"), time.Since(t0).Milliseconds(), err)
	if err != nil {
		if strings.Contains(err.Error(), "no available vendor support") {
			return getLegacyURL(url)
		}
		return "", err
	}

	var v struct {
		Vendor struct {
			ID     byte `json:"vendor"`
			Params struct {
				UID string `json:"p2p_id"`
			} `json:"vendor_params"`
		} `json:"vendor"`
		PublicKey string `json:"public_key"`
		Sign      string `json:"sign"`
	}
	if err = json.Unmarshal(res, &v); err != nil {
		return "", err
	}

	query.Set("client_public", hex.EncodeToString(clientPublic))
	query.Set("client_private", hex.EncodeToString(clientPrivate))
	query.Set("device_public", v.PublicKey)
	query.Set("sign", v.Sign)
	query.Set("vendor", getVendorName(v.Vendor.ID))

	if v.Vendor.ID == 1 {
		query.Set("uid", v.Vendor.Params.UID)
	}

	// cs2 cloud-relay mode: cameras of the MJA1-secure-element generation
	// (e.g. xiaomi.camera.c302n) cannot be reached on the LAN port — they
	// only stream via the Mi-Cloud relay. Pass the p2p_id through and
	// redirect the host to the relay; the miss client picks this up and
	// runs the cloud handshake.
	if v.Vendor.ID == 4 && v.Vendor.Params.UID != "" {
		query.Set("p2p_id", v.Vendor.Params.UID)
		if relay := query.Get("relay"); relay != "" {
			// relay=A,B,C: dial A; the miss client falls back to B, then C.
			relays := strings.Split(relay, ",")
			relay = relays[0]
			if len(relays) > 1 {
				query.Set("relay_alt", strings.Join(relays[1:], ","))
			}
			log.Debug().Msgf("xiaomi: cs2 cloud-relay override to %s", relay)
			url.Host = relay
		} else {
			log.Debug().Msgf("xiaomi: cs2 cloud-relay mode, redirecting to %s", cs2CloudRelayHost)
			url.Host = cs2CloudRelayHost
		}
	}

	url.RawQuery = query.Encode()
	return url.String(), nil
}

func getVendorName(i byte) string {
	switch i {
	case 1:
		return "tutk"
	case 3:
		return "agora"
	case 4:
		return "cs2"
	case 6:
		return "mtp"
	}
	return fmt.Sprintf("%d", i)
}

func wakeUpCamera(url *url.URL) error {
	const params = `{"id":1,"method":"wakeup","params":{"video":"1"}}`
	did := url.Query().Get("did")
	_, err := cloudUserRequest(url.User, "/home/rpc/"+did, params)
	return err
}

func apiXiaomi(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		apiDeviceList(w, r)
	case "POST":
		apiAuth(w, r)
	}
}

func apiDeviceList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	user := query.Get("id")
	if user == "" {
		cloudsMu.Lock()
		users := make([]string, 0, len(tokens))
		for s := range tokens {
			users = append(users, s)
		}
		cloudsMu.Unlock()

		api.ResponseJSON(w, users)
		return
	}

	err := func() error {
		region := query.Get("region")
		res, err := cloudRequest(user, region, "/v2/home/device_list_page", "{}")
		if err != nil {
			return err
		}
		var v struct {
			List []*Device `json:"list"`
		}

		log.Trace().Str("user", user).Msgf("[xiaomi] devices list: %s", res)

		if err = json.Unmarshal(res, &v); err != nil {
			return err
		}

		var items []*api.Source

		for _, device := range v.List {
			if !device.HasCamera() {
				continue
			}
			items = append(items, &api.Source{
				Name: device.Name,
				Info: fmt.Sprintf("ip: %s, mac: %s", device.IP, device.MAC),
				URL:  fmt.Sprintf("xiaomi://%s:%s@%s?did=%s&model=%s", user, region, device.IP, device.Did, device.Model),
			})
		}

		api.ResponseSources(w, items)
		return nil
	}()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type Device struct {
	Did   string `json:"did"`
	Name  string `json:"name"`
	Model string `json:"model"`
	MAC   string `json:"mac"`
	IP    string `json:"localip"`
}

func (d *Device) HasCamera() bool {
	return strings.Contains(d.Model, ".camera.") ||
		strings.Contains(d.Model, ".cateye.") ||
		strings.Contains(d.Model, ".feeder.")
}

var auth *xiaomi.Cloud

func apiAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")
	captcha := r.Form.Get("captcha")
	verify := r.Form.Get("verify")

	var err error

	switch {
	case username != "" || password != "":
		auth = xiaomi.NewCloud(AppXiaomiHome)
		err = auth.Login(username, password)
	case captcha != "":
		err = auth.LoginWithCaptcha(captcha)
	case verify != "":
		err = auth.LoginWithVerify(verify)
	default:
		http.Error(w, "wrong request", http.StatusBadRequest)
		return
	}

	if err == nil {
		userID, token := auth.UserToken()
		auth = nil

		cloudsMu.Lock()
		if tokens == nil {
			tokens = map[string]string{userID: token}
		} else {
			tokens[userID] = token
		}
		cloudsMu.Unlock()

		err = app.PatchConfig([]string{"xiaomi", userID}, token)
	}

	if err != nil {
		var login *xiaomi.LoginError
		if errors.As(err, &login) {
			w.Header().Set("Content-Type", api.MimeJSON)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(err)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const AppXiaomiHome = "xiaomiio"

func GetBaseURL(region string) string {
	switch region {
	case "de", "i2", "ru", "sg", "us":
		return "https://" + region + ".api.io.mi.com/app"
	}
	return "https://api.io.mi.com/app"
}

type missCtl interface {
	SetQuality(q string) error
	Motor(dir string) error
}

// apiXiaomiCtl changes quality or moves the camera inside the stream's live
var flipCache sync.Map // did -> flipEntry

type flipEntry struct {
	on bool
	at time.Time
}

// imageFlipped says (from a cache refreshed every 6 h) whether the camera
// picture is rotated 180 degrees. Unknown means not flipped.
func imageFlipped(user *url.Userinfo, did string) bool {
	if v, ok := flipCache.Load(did); ok {
		return v.(flipEntry).on
	}
	return refreshFlip(user, did)
}

// refreshFlip reads the camera flip setting from the cloud and caches it.
func refreshFlip(user *url.Userinfo, did string) bool {
	if v, ok := flipCache.Load(did); ok && time.Since(v.(flipEntry).at) < 5*time.Hour {
		return v.(flipEntry).on
	}
	res, err := cloudUserRequest(user, "/home/rpc/"+did, `{"id":1,"method":"get_prop","params":["flip"]}`)
	on := err == nil && strings.Contains(string(res), `"on"`)
	known := on || (err == nil && strings.Contains(string(res), `"off"`))
	log.Info().Msgf("[xiaomi] flip did=%s: %s err=%v -> %v", did, res, err, on)
	if known {
		flipCache.Store(did, flipEntry{on: on, at: time.Now()})
	} else if v, ok := flipCache.Load(did); ok {
		// No answer (a sleeping or remote camera answers empty): keep what
		// it said before, and ask again on the next move.
		return v.(flipEntry).on
	}
	return on
}

// session: ?src=cam2&quality=hd or ?src=cam2&motor=left.
func apiXiaomiCtl(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stream := streams.Get(q.Get("src"))
	if stream == nil {
		http.Error(w, "unknown stream", http.StatusNotFound)
		return
	}
	if dir := q.Get("motor"); dir != "" {
		// Xiaomi set_motor operations for an upright camera: 1 left, 2 right,
		// 3 up, 4 down (the gate, mounted flipped, needs them swapped).
		// A camera mounted upside down with image flip on moves the other
		// way on screen; Xiaomi Home swaps directions then, so do we.
		flipped := false
		for _, raw := range stream.SourceURLs() {
			if u, err := url.Parse(raw); err == nil && strings.HasPrefix(raw, "xiaomi://") {
				flipped = imageFlipped(u.User, u.Query().Get("did"))
				break
			}
		}
		if flipped {
			dir = map[string]string{"left": "right", "right": "left", "up": "down", "down": "up"}[dir]
		}
		op := map[string]int{"left": 1, "right": 2, "up": 3, "down": 4}[dir]
		if op == 0 {
			http.Error(w, "motor: left, right, up or down", http.StatusBadRequest)
			return
		}
		// via=p2p: the step over the open camera session (~20 ms). Not the
		// default: cameras answered "ok" and did not move. The cloud below
		// moves every model.
		if q.Get("via") == "p2p" {
			src := strings.TrimSuffix(q.Get("src"), "_sd")
			for _, name := range []string{src, src + "_sd"} {
				s := streams.Get(name)
				if s == nil {
					continue
				}
				for _, c := range s.LiveConns() {
					if m, ok := c.(missCtl); ok {
						t0 := time.Now()
						err := m.Motor(dir)
						log.Info().Msgf("[xiaomi] motor p2p %s %s in %dms err=%v", name, dir, time.Since(t0).Milliseconds(), err)
						if err == nil {
							_, _ = w.Write([]byte("ok"))
							return
						}
					}
				}
			}
		}
		for _, raw := range stream.SourceURLs() {
			if !strings.HasPrefix(raw, "xiaomi://") {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			did := u.Query().Get("did")
			params := fmt.Sprintf(`{"id":1,"method":"set_motor","params":{"operation":%d}}`, op)
			t0 := time.Now()
			res, err := cloudUserRequest(u.User, "/home/rpc/"+did, params)
			log.Info().Msgf("[xiaomi] motor did=%s %s in %dms: %s err=%v", did, dir, time.Since(t0).Milliseconds(), res, err)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			_, _ = w.Write(res)
			return
		}
		http.Error(w, "no xiaomi source", http.StatusNotFound)
		return
	}
	for _, c := range stream.LiveConns() {
		m, ok := c.(missCtl)
		if !ok {
			continue
		}
		var err error
		if v := q.Get("quality"); v != "" {
			err = m.SetQuality(v)
		} else if v := q.Get("motor"); v != "" {
			err = m.Motor(v)
		} else {
			http.Error(w, "quality or motor required", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("ok"))
		return
	}
	http.Error(w, "no live session", http.StatusConflict)
}
