package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/cache"
	"github.com/go-gost/x/registry"
)

// swagger:parameters getCacheListRequest
type getCacheListRequest struct{}

// successful operation.
// swagger:response getCacheListResponse
type getCacheListResponse struct {
	// in: body
	Data cacheList
}

type cacheList struct {
	Count int                  `json:"count"`
	List  []*config.CacheConfig `json:"list"`
}

func getCacheList(ctx *gin.Context) {
	// swagger:route GET /config/caches Cache getCacheListRequest
	//
	// Get cache list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getCacheListResponse

	var req getCacheListRequest
	ctx.ShouldBindQuery(&req)

	list := config.Global().Caches

	ctx.JSON(http.StatusOK, Response{
		Data: cacheList{
			Count: len(list),
			List:  list,
		},
	})
}

// swagger:parameters getCacheRequest
type getCacheRequest struct {
	// in: path
	// required: true
	Cache string `uri:"cache" json:"cache"`
}

// successful operation.
// swagger:response getCacheResponse
type getCacheResponse struct {
	// in: body
	Data *config.CacheConfig
}

func getCache(ctx *gin.Context) {
	// swagger:route GET /config/caches/{cache} Cache getCacheRequest
	//
	// Get cache.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getCacheResponse

	var req getCacheRequest
	ctx.ShouldBindUri(&req)

	var resp getCacheResponse
	for _, c := range config.Global().Caches {
		if c == nil {
			continue
		}
		if c.Name == req.Cache {
			resp.Data = c
			break
		}
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters createCacheRequest
type createCacheRequest struct {
	// in: body
	Data config.CacheConfig `json:"data"`
}

// successful operation.
// swagger:response createCacheResponse
type createCacheResponse struct {
	Data Response
}

func createCache(ctx *gin.Context) {
	// swagger:route POST /config/caches Cache createCacheRequest
	//
	// Create a new cache, the name of the cache must be unique in cache list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createCacheResponse

	var req createCacheRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "cache name is required"))
		return
	}
	req.Data.Name = name

	if registry.CacheRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("cache %s already exists", name)))
		return
	}

	v := parser.ParseCache(&req.Data)
	if v == nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "cache has no backend configured"))
		return
	}

	if err := registry.CacheRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("cache %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Caches = append(c.Caches, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateCacheRequest
type updateCacheRequest struct {
	// in: path
	// required: true
	Cache string `uri:"cache" json:"cache"`
	// in: body
	Data config.CacheConfig `json:"data"`
}

// successful operation.
// swagger:response updateCacheResponse
type updateCacheResponse struct {
	Data Response
}

func updateCache(ctx *gin.Context) {
	// swagger:route PUT /config/caches/{cache} Cache updateCacheRequest
	//
	// Update cache by name, the cache must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateCacheResponse

	var req updateCacheRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Cache)

	if !registry.CacheRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("cache %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseCache(&req.Data)
	if v == nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "cache has no backend configured"))
		return
	}

	registry.CacheRegistry().Unregister(name)

	if err := registry.CacheRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("cache %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Caches {
			if c.Caches[i].Name == name {
				c.Caches[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteCacheRequest
type deleteCacheRequest struct {
	// in: path
	// required: true
	Cache string `uri:"cache" json:"cache"`
}

// successful operation.
// swagger:response deleteCacheResponse
type deleteCacheResponse struct {
	Data Response
}

func deleteCache(ctx *gin.Context) {
	// swagger:route DELETE /config/caches/{cache} Cache deleteCacheRequest
	//
	// Delete cache by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteCacheResponse

	var req deleteCacheRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Cache)

	if !registry.CacheRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("cache %s not found", name)))
		return
	}
	registry.CacheRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		caches := c.Caches
		c.Caches = nil
		for _, s := range caches {
			if s.Name == name {
				continue
			}
			c.Caches = append(c.Caches, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
