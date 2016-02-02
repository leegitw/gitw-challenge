package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/ant0ine/go-json-rest/rest"
)

const HTTP_PORT = 8088
const CACHE_KEY_PREFIX = "chall3"
const CACHE_KEY_VERSION = "v1"
const STORE_DIR = "store"

var store = map[string]*CacheEntry{}
var storeStats = map[string]int{}

var lockStore = &sync.Mutex{}
var lockStats = &sync.Mutex{}

func initStore() {

	fileList := []string{}
	statList := []string{}
	err := filepath.Walk(STORE_DIR, func(path string, f os.FileInfo, err error) error {
		if strings.HasSuffix(path, "json") == true {
			fileList = append(fileList, path)
		} else if strings.HasSuffix(path, "cnt") == true {
			statList = append(statList, path)
		}
		return nil
	})

	lockStore.Lock()
	for _, fp := range fileList {
		b, _ := ioutil.ReadFile(fp)

		fName := filepath.Base(fp)
		extName := filepath.Ext(fp)
		key := fName[:len(fName)-len(extName)]

		item := &CacheEntry{}
		err = json.Unmarshal(b, &item)
		if err == nil {
			switch item.valueType {
			case "string":
				sc := item.Value.(string)
				item.Value = sc
			case "int":
				sc := item.Value.(int)
				item.Value = sc
			case "float64":
				sc := item.Value.(float64)
				item.Value = sc
			case "bool":
				sc := item.Value.(bool)
				item.Value = sc
			}

			store[key] = item
		}
	}
	lockStore.Unlock()

	lockStats.Lock()
	for _, fp := range statList {
		b, _ := ioutil.ReadFile(fp)
		bStr := string(b)

		fName := filepath.Base(fp)
		extName := filepath.Ext(fp)
		key := fName[:len(fName)-len(extName)]
		storeStats[key] = len(bStr)
	}
	lockStats.Unlock()
}

func main() {

	initStore()

	var mStack = []rest.Middleware{
		&rest.AccessLogApacheMiddleware{
			Format: rest.CombinedLogFormat,
		},
		&rest.RecoverMiddleware{},
	}

	var err error
	api := rest.NewApi()
	api.Use(mStack...)

	/* api.Use(&rest.CorsMiddleware{
		RejectNonCorsRequests: false,
		OriginValidator: func(origin string, request *rest.Request) bool {
			return true
		},
		AllowedMethods: []string{"GET", "POST", "PUT"},
		AllowedHeaders: []string{
			"Accept", "Content-Type", "X-Custom-Header", "Origin", "Session-Token",
			"X-Forwarded-For", "x-forwarded-for", "X-FORWARDED-FOR",
		},
		AccessControlAllowCredentials: true,
		AccessControlMaxAge:           3600,
	}) */

	router, err := rest.MakeRouter(
		&rest.Route{"POST", "/cache", handleCachePost},
		&rest.Route{"GET", "/cache", handleCacheGet},
		&rest.Route{"DELETE", "/cache", handleCacheDelete},
		&rest.Route{"POST", "/cache/", handleCachePost},
		&rest.Route{"GET", "/cache/", handleCacheGet},
		&rest.Route{"DELETE", "/cache/", handleCacheDelete},

		&rest.Route{"PUT", "/cache/:key", handleCacheKeyPost},
		&rest.Route{"GET", "/cache/:key", handleCacheKeyGet},
		&rest.Route{"GET", "/cache/:key/:value", handleCacheKeyGetAdd},
		&rest.Route{"DELETE", "/cache/:key", handleCacheKeyDelete},
	)
	if err != nil {
		log.Fatal(err)
	}

	api.SetApp(router)

	http.Handle("/", api.MakeHandler())

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", HTTP_PORT), nil))
}

func handleCachePost(w rest.ResponseWriter, r *rest.Request) {

	item := &CacheEntry{}
	err := r.DecodeJsonPayload(&item)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	key, err := item.GetCacheKey()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	lockStore.Lock()
	_, ok := store[key]
	if !ok {
		var obj = reflect.ValueOf(&item.Value)
		switch obj.Elem().Interface().(type) {
		case string:
			item.valueType = "string"
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			item.valueType = "int"
		case float32, float64:
			item.valueType = "float64"
		case bool:
			item.valueType = "bool"
		}

		store[key] = item
		item.WriteLocal(key)
	}
	lockStore.Unlock()

	if ok {
		w.WriteHeader(http.StatusConflict)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func handleCacheKeyPost(w rest.ResponseWriter, r *rest.Request) {
	keyStr, _ := url.QueryUnescape(r.PathParam("key"))

	item := &CacheEntry{}
	err := r.DecodeJsonPayload(&item)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	key, err := item.GetCacheKey()
	if len(key) == 0 {
		item.Key = keyStr
		key, err = item.GetCacheKey()
	}

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	lockStore.Lock()
	_, ok := store[key]
	if ok {
		var obj = reflect.ValueOf(&item.Value)
		switch obj.Elem().Interface().(type) {
		case string:
			item.valueType = "string"
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			item.valueType = "int"
		case float32, float64:
			item.valueType = "float64"
		case bool:
			item.valueType = "bool"
		}

		store[key] = item
		item.WriteLocal(key)
	}
	lockStore.Unlock()

	if ok {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func handleCacheKeyGetAdd(w rest.ResponseWriter, r *rest.Request) {
	keyStr, _ := url.QueryUnescape(r.PathParam("key"))
	value, _ := url.QueryUnescape(r.PathParam("value"))

	item := &CacheEntry{
		Key:   keyStr,
		Value: value,
	}

	key, err := item.GetCacheKey()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	lockStore.Lock()
	store[key] = item
	item.WriteLocal(key)
	lockStore.Unlock()

	w.WriteHeader(http.StatusAccepted)
}

func handleCacheGet(w rest.ResponseWriter, r *rest.Request) {
	res := CacheResMulti{}
	lockStore.Lock()
	lockStats.Lock()
	for key, item := range store {
		if curCnt, ok := storeStats[key]; ok {
			curCnt++

			if curCnt >= 100 {
				delete(store, key)
				delete(storeStats, key)

				item.DeleteLocal(key)
			} else {
				storeStats[key] = curCnt
				item.IncLocal(key, false)
			}
		} else {
			storeStats[key] = 1
		}

		res.Items = append(res.Items, *item)
	}
	lockStore.Unlock()
	lockStats.Unlock()

	w.WriteJson(res)
}

func handleCacheKeyGet(w rest.ResponseWriter, r *rest.Request) {
	keyStr, _ := url.QueryUnescape(r.PathParam("key"))

	item := &CacheEntry{
		Key: keyStr,
	}

	key, err := item.GetCacheKey()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	svals := []string{
		key,
	}

	if keyStr != "" {
		switch key := item.Key.(type) {
		case string:
			if _, err := strconv.Atoi(key); err == nil {
				svals = append(svals, "i"+GetMD5Hash(key))
			}
		}
	}

	var ok bool
	lockStore.Lock()
	lockStats.Lock()
	for _, skey := range svals {
		item, ok = store[skey]
		if ok == true {
			if curCnt, ok := storeStats[skey]; ok {
				curCnt++

				if curCnt >= 100 {
					delete(store, skey)
					delete(storeStats, skey)

					item.DeleteLocal(skey)
				} else {
					storeStats[skey] = curCnt
					item.IncLocal(skey, false)
				}
			} else {
				storeStats[skey] = 1
			}

			break
		}
	}
	lockStore.Unlock()
	lockStats.Unlock()

	if ok {
		w.WriteHeader(http.StatusOK)
		w.WriteJson(item)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func handleCacheDelete(w rest.ResponseWriter, r *rest.Request) {
	lockStore.Lock()

	store = map[string]*CacheEntry{}

	err := filepath.Walk(STORE_DIR, func(path string, f os.FileInfo, err error) error {
		if strings.HasSuffix(path, "json") == true || strings.HasSuffix(path, "cnt") == true {
			os.Remove(path)
		}
		return nil
	})

	lockStore.Unlock()

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleCacheKeyDelete(w rest.ResponseWriter, r *rest.Request) {
	keyStr, _ := url.QueryUnescape(r.PathParam("key"))

	item := &CacheEntry{
		Key: keyStr,
	}

	key, err := item.GetCacheKey()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	svals := []string{
		key,
	}

	if keyStr != "" {
		switch key := item.Key.(type) {
		case string:
			if _, err := strconv.Atoi(key); err == nil {
				svals = append(svals, "i"+GetMD5Hash(key))
			} else if key == "true" || key == "false" {
				svals = append(svals, "b"+GetMD5Hash(key))
			}
		}
	}

	var ok bool
	lockStore.Lock()
	lockStats.Lock()
	for _, skey := range svals {
		item, ok = store[skey]
		if ok == true {
			delete(store, skey)
			delete(storeStats, skey)
			item.DeleteLocal(skey)
			break
		}
	}
	lockStore.Unlock()
	lockStats.Unlock()

	if ok {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

type CacheResMulti struct {
	Items []CacheEntry `json:"cache"`
}

type CacheEntry struct {
	Key       interface{} `json:"key"`
	Value     interface{} `json:"value"`
	valueType string      `json:"value_type"`
}

func (item CacheEntry) GetCacheKey() (string, error) {
	switch key := item.Key.(type) {
	case string:
		return "s" + GetMD5Hash(key), nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "i" + GetMD5Hash(fmt.Sprintf("%d", key)), nil
	case float32, float64:
		ks := fmt.Sprintf("%v", key)
		if strings.Contains(ks, ".") == false {
			return "i" + GetMD5Hash(ks), nil
		}
		return "f" + GetMD5Hash(ks), nil
	case bool:
		if key == true {
			return "b" + GetMD5Hash("true"), nil
		} else {
			return "b" + GetMD5Hash("false"), nil
		}
	}

	return "", fmt.Errorf("No cast defined for %v", item.Key)
}

func (item *CacheEntry) DeleteLocal(key string) error {
	fpaths := []string{
		fmt.Sprintf("%s/%s.json", STORE_DIR, key),
		fmt.Sprintf("%s/%s.cnt", STORE_DIR, key),
	}

	for _, fpath := range fpaths {
		os.Remove(fpath)
	}

	return nil
}

func (item *CacheEntry) WriteLocal(key string) error {
	fpath := fmt.Sprintf("%s/%s.json", STORE_DIR, key)

	b, err := json.Marshal(item)
	if err == nil {
		err = ioutil.WriteFile(fpath, b, 0644)
	}

	return nil
}

func (item *CacheEntry) IncLocal(key string, doReset bool) error {
	fpath := fmt.Sprintf("%s/%s.cnt", STORE_DIR, key)

	if doReset == true {
		//log.Println("do inc reset")
		return ioutil.WriteFile(fpath, []byte("1"), 0644)
	} else if _, err := os.Stat(fpath); os.IsNotExist(err) {
		//log.Println("file doest exists")
		return ioutil.WriteFile(fpath, []byte("1"), 0644)
	}

	f, err := os.OpenFile(fpath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString("1"); err != nil {
		return err
	}

	return nil
}

func GetMD5Hash(text string) string {
	hasher := md5.New()
	b := []byte(text)
	_, _ = hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}
