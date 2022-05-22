package sca

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/allegro/bigcache/v3"

	"mosn.io/mosn/pkg/log"
)

var cacher cache

func init() {
	cacher = cache{
		delegator: mustNewBigCache(),
	}
}

func mustNewBigCache() *bigcache.BigCache {
	var c, err = newBigCache()
	if err != nil {
		panic(err)
	}
	return c
}

func newBigCache() (*bigcache.BigCache, error) {
	// each shard initializes with `(MaxEntriesInWindows / Shards) * MaxEntrySize` = 512 * 600 = 300kb
	// each shard limits in `(HardMaxCacheSize * 1024 * 1024) / Shards` = 1024 * 1024 * 1024 / 256 = 4mb
	// initializes with 256 * 300kb = 75mb, limits with 256 * 4mb = 1gb.
	var config = bigcache.Config{
		LifeWindow:         10 * time.Minute,
		CleanWindow:        5 * time.Minute,
		Shards:             256,
		MaxEntriesInWindow: 256 * 10 * 60,
		MaxEntrySize:       512,
		HardMaxCacheSize:   1024,
		StatsEnabled:       false,
		Verbose:            false,
		OnRemoveWithReason: func(key string, entry []byte, reason bigcache.RemoveReason) {
			if reason == bigcache.Deleted {
				return
			}
			var reasonDesc = "unknown"
			switch reason {
			case bigcache.Expired:
				reasonDesc = "expired"
			case bigcache.NoSpace:
				reasonDesc = "nospace"
			}
			log.DefaultLogger.Infof("[cache] %s removed as %s, size: %d", key, reasonDesc, len(entry))
		},
		Logger: cacheLogger(func(f string, v ...interface{}) {
			log.DefaultLogger.Infof(f, v...)
		}),
		Hasher: cacheHasher(func(s string) uint64 {
			var h = fnv.New64a()
			_, _ = h.Write([]byte(s))
			return h.Sum64()
		}),
	}

	var provider, err = bigcache.NewBigCache(config)
	if err != nil {
		return nil, fmt.Errorf("error creating memory cacher: %w", err)
	}
	return provider, nil
}

type cacheHasher func(string) uint64

func (f cacheHasher) Sum64(s string) uint64 {
	return f(s)
}

type cacheLogger func(string, ...interface{})

func (f cacheLogger) Printf(format string, v ...interface{}) {
	f(format, v...)
}

type cache struct {
	delegator *bigcache.BigCache
}

func (c cache) Get(key string) ([]byte, error) {
	var bs, err = c.delegator.Get(key)
	if err != nil {
		return nil, err
	}
	if bs == nil {
		return nil, errors.New("unable to retrieve data from bigcache")
	}
	return bs, nil
}

func (c cache) GetObject(key string, objReceiver interface{}) error {
	var bs, err = c.Get(key)
	if err != nil {
		return fmt.Errorf("error get object bytes from cache: %w", err)
	}
	var dec = gob.NewDecoder(bytes.NewBuffer(bs))
	err = dec.Decode(objReceiver)
	if err != nil {
		return fmt.Errorf("error decoding object from bytes: %w", err)
	}
	return nil
}

func (c cache) Set(key string, bs []byte) error {
	var err = c.delegator.Set(key, bs)
	if err != nil {
		return fmt.Errorf("error set object bytes into cache: %w", err)
	}
	return nil
}

func (c cache) SetObject(key string, obj interface{}) error {
	var bs bytes.Buffer
	var enc = gob.NewEncoder(&bs)
	var err = enc.Encode(obj)
	if err != nil {
		return fmt.Errorf("error encoding object to bytes: %w", err)
	}
	return c.Set(key, bs.Bytes())
}
