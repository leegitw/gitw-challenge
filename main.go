package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"crypto/md5"
	"encoding/hex"
	"sync"
	"os"
	"io/ioutil"
	"net/url"

	"github.com/ant0ine/go-json-rest/rest"
)

const HTTP_PORT = 8088
const MEMCACHE_HOST = "localhost"
const MEMCACHE_PORT = 11211
const CACHE_KEY_PREFIX = "chall3"
const CACHE_KEY_VERSION = "v1"
const STORE_DIR = "/Users/leebrown/go/src/github.com/leetune/chall3/store"

var store = map[string]*CacheEntry{}
var storeStats = map[string]int{}

var lockStore = sync.RWMutex{}
var lockStats = sync.RWMutex{}

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

    log.Println(fileList)

    lockStore.Lock()
    for _, fp := range fileList {
		b, _ := ioutil.ReadFile(fp)

		item := &CacheEntry{}
		err = json.Unmarshal(b, &item)
		if err == nil {
			key, err := item.GetCacheKey()
			if err == nil {
				store[key] = item 
			}
		}
    }
    lockStore.Unlock()


	lockStats.Lock()
    for _, fp := range statList {
		b, _ := ioutil.ReadFile(fp)
		bStr := string(b)

		fName := filepath.Base(fp)
		extName := filepath.Ext(fp)
		bName := fName[:len(fName)-len(extName)]
		storeStats[bName] = len(bStr)
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
	if ok {
		w.WriteHeader(http.StatusConflict)
	} else {
		w.WriteHeader(http.StatusCreated)
		store[key] = item
	}
	lockStore.Unlock()

	if ok == false {
		go item.WriteLocal()
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

    log.Println("put", key, item.Key, "->", item.Value)

	lockStore.Lock()
	curItem, ok := store[key]
	if ok {
		log.Println("hit", key, curItem.Key, "->", curItem.Value)
		w.WriteHeader(http.StatusNoContent)
		store[key] = item
	} else {
		log.Println("miss", key)

		w.WriteHeader(http.StatusNotFound)
	}    
    lockStore.Unlock()

    if ok == false {
    	go item.WriteLocal()
    }
}

func handleCacheKeyGetAdd(w rest.ResponseWriter, r *rest.Request) {
	keyStr, _ := url.QueryUnescape(r.PathParam("key"))
	value, _ := url.QueryUnescape(r.PathParam("value"))

	item := &CacheEntry{
		Key: keyStr,
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
    lockStore.Unlock()
    w.WriteHeader(http.StatusAccepted)

    go item.WriteLocal()
}

func handleCacheGet(w rest.ResponseWriter, r *rest.Request) {	
	lockStore.RLock()
    curItems := store
    lockStore.RUnlock()

	res := CacheResMulti{}

	for _, item := range curItems {
		res.Items = append(res.Items, *item)
	}

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

	lockStore.RLock()
	item, ok := store[key]
	lockStore.RUnlock()

	if ok {
    	w.WriteJson(item)
    	w.WriteHeader(http.StatusOK)

	    doReset := false
		lockStats.Lock()
		if curCnt, ok := storeStats[key]; ok {
			if curCnt >= 100 {
					storeStats[key] = 0
					doReset = true

					lockStore.Lock()
					delete(store, key)
					lockStore.Unlock()

					item.DeleteLocal()
				} else {
					storeStats[key]++

				}
	    } else {
	    	storeStats[key] = 1
	    }
	    lockStats.Unlock()

	    go item.IncLocal(doReset)    	
    } else {
    	w.WriteHeader(http.StatusNotFound)
    }  
}

func handleCacheDelete(w rest.ResponseWriter, r *rest.Request) {
	lockStore.RLock()
    store = map[string]*CacheEntry{}
    lockStore.RUnlock()

    err := filepath.Walk(STORE_DIR, func(path string, f os.FileInfo, err error) error {
    	if strings.HasSuffix(path, "json") == true ||  strings.HasSuffix(path, "cnt") == true {
    	os.Remove(path)
    }
        return nil
    })

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

	lockStore.Lock()
	item, ok := store[key]
	if ok {
		delete(store, key)

    	w.WriteHeader(http.StatusNoContent)
    } else {
    	w.WriteHeader(http.StatusNotFound)
    }
    lockStore.Unlock()

	if ok {
		go item.DeleteLocal()
    } 
}

type CacheResMulti struct {
	Items []CacheEntry `json:"cache"`
}

type CacheEntry struct {
	Key interface{} `json:"key"`
	Value interface{} `json:"value"`
}

func (item CacheEntry) GetCacheKey() (string, error) {
	switch key := item.Key.(type) {
        case string:
            return "s"+GetMD5Hash(key), nil
        case int,int8,int16,int32,int64,uint,uint8,uint16,uint32,uint64:
            return "i"+GetMD5Hash(fmt.Sprintf("%d", key)), nil
        case float32, float64:
        	return "f"+GetMD5Hash(fmt.Sprintf("%v", key)), nil
        case bool:
        	if key == true {
        		return "b"+GetMD5Hash("true"), nil
        	} else {
        		return "b"+GetMD5Hash("false"), nil
        	}
    }

    return "", fmt.Errorf("No cast defined for %v", item.Key)
}

func (item *CacheEntry) DeleteLocal() (error) {
	key, _ := item.GetCacheKey()

	fpaths :=[]string{
		fmt.Sprintf("%s/%s.json", STORE_DIR, key),
		fmt.Sprintf("%s/%s.cnt", STORE_DIR, key),
	}

	for _, fpath := range fpaths {
		os.Remove(fpath)
	}

	return nil
}

func (item *CacheEntry) WriteLocal() (error) {
	key, _ := item.GetCacheKey()
	fpath := fmt.Sprintf("%s/%s.json", STORE_DIR, key)

	b, err := json.Marshal(item)
	if err == nil {
		err = ioutil.WriteFile(fpath, b, 0644)
	}

	return nil
}

func (item *CacheEntry) IncLocal(doReset bool) (error) {
	key, _ := item.GetCacheKey()
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
