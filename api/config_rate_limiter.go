package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/limiter"
	"github.com/go-gost/x/registry"
)

// swagger:parameters getRateLimiterListRequest
type getRateLimiterListRequest struct {
}

// successful operation.
// swagger:response getRateLimiterListResponse
type getRateLimiterListResponse struct {
	// in: body
	Data rateLimiterList
}

type rateLimiterList struct {
	Count int                       `json:"count"`
	List  []*config.LimiterConfig `json:"list"`
}

func getRateLimiterList(ctx *gin.Context) {
	// swagger:route GET /config/rlimiters Limiter getRateLimiterListRequest
	//
	// Get rate limiter list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getRateLimiterListResponse

	var req getRateLimiterListRequest
	ctx.ShouldBindQuery(&req)

	list := config.Global().CLimiters

	var resp getRateLimiterListResponse
	resp.Data = rateLimiterList{
		Count: len(list),
		List:  list,
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters getRateLimiterRequest
type getRateLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"limiter" json:"limiter"`
}

// successful operation.
// swagger:response getRateLimiterResponse
type getRateLimiterResponse struct {
	// in: body
	Data *config.LimiterConfig
}

func getRateLimiter(ctx *gin.Context) {
	// swagger:route GET /config/rlimiters/{limiter} Limiter getRateLimiterRequest
	//
	// Get conn limiter.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getRateLimiterResponse

	var req getRateLimiterRequest
	ctx.ShouldBindUri(&req)

	var resp getRateLimiterResponse

	for _, limiter := range config.Global().CLimiters{
		if limiter == nil {
			continue
		}
		if limiter.Name == req.Limiter {
			resp.Data = limiter
		}
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters createRateLimiterRequest
type createRateLimiterRequest struct {
	// in: body
	Data config.LimiterConfig `json:"data"`
}

// successful operation.
// swagger:response createRateLimiterResponse
type createRateLimiterResponse struct {
	Data Response
}

func createRateLimiter(ctx *gin.Context) {
	// swagger:route POST /config/rlimiters Limiter createRateLimiterRequest
	//
	// Create a new rate limiter, the name of limiter must be unique in limiter list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createRateLimiterResponse

	var req createRateLimiterRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "limiter name is required"))
		return
	}
	req.Data.Name = name

	if registry.RateLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("limiter %s already exists", name)))
		return
	}

	v := parser.ParseRateLimiter(&req.Data)

	if err := registry.RateLimiterRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("limiter %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.RLimiters = append(c.RLimiters, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateRateLimiterRequest
type updateRateLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"limiter" json:"limiter"`
	// in: body
	Data config.LimiterConfig `json:"data"`
}

// successful operation.
// swagger:response updateRateLimiterResponse
type updateRateLimiterResponse struct {
	Data Response
}

func updateRateLimiter(ctx *gin.Context) {
	// swagger:route PUT /config/rlimiters/{limiter} Limiter updateRateLimiterRequest
	//
	// Update rate limiter by name, the limiter must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateRateLimiterResponse

	var req updateRateLimiterRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Limiter)

	if !registry.RateLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("limiter %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseRateLimiter(&req.Data)

	registry.RateLimiterRegistry().Unregister(name)

	if err := registry.RateLimiterRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("limiter %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.RLimiters {
			if c.RLimiters[i].Name == name {
				c.RLimiters[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteRateLimiterRequest
type deleteRateLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"limiter" json:"limiter"`
}

// successful operation.
// swagger:response deleteRateLimiterResponse
type deleteRateLimiterResponse struct {
	Data Response
}

func deleteRateLimiter(ctx *gin.Context) {
	// swagger:route DELETE /config/rlimiters/{limiter} Limiter deleteRateLimiterRequest
	//
	// Delete rate limiter by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteRateLimiterResponse

	var req deleteRateLimiterRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Limiter)

	if !registry.RateLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("limiter %s not found", name)))
		return
	}
	registry.RateLimiterRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		limiteres := c.RLimiters
		c.RLimiters = nil
		for _, s := range limiteres {
			if s.Name == name {
				continue
			}
			c.RLimiters = append(c.RLimiters, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
