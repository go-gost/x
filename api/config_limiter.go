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

// swagger:parameters getLimiterListRequest
type getLimiterListRequest struct {
}

// successful operation.
// swagger:response getLimiterListResponse
type getLimiterListResponse struct {
	// in: body
	Data limiterList
}

type limiterList struct {
	Count int                       `json:"count"`
	List  []*config.LimiterConfig `json:"list"`
}

func getLimiterList(ctx *gin.Context) {
	// swagger:route GET /config/limiters Limiter getLimiterListRequest
	//
	// Get limiter list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getLimiterListResponse

	var req getLimiterListRequest
	ctx.ShouldBindQuery(&req)

	list := config.Global().Limiters

	var resp getLimiterListResponse
	resp.Data = limiterList{
		Count: len(list),
		List:  list,
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters getLimiterRequest
type getLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"limiter" json:"limiter"`
}

// successful operation.
// swagger:response getLimiterResponse
type getLimiterResponse struct {
	// in: body
	Data *config.LimiterConfig
}

func getLimiter(ctx *gin.Context) {
	// swagger:route GET /config/limiters/{limiter} Limiter getLimiterRequest
	//
	// Get limiter.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getLimiterResponse

	var req getLimiterRequest
	ctx.ShouldBindUri(&req)

	var resp getLimiterResponse

	for _, limiter := range config.Global().Limiters {
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

// swagger:parameters createLimiterRequest
type createLimiterRequest struct {
	// in: body
	Data config.LimiterConfig `json:"data"`
}

// successful operation.
// swagger:response createLimiterResponse
type createLimiterResponse struct {
	Data Response
}

func createLimiter(ctx *gin.Context) {
	// swagger:route POST /config/limiters Limiter createLimiterRequest
	//
	// Create a new limiter, the name of limiter must be unique in limiter list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createLimiterResponse

	var req createLimiterRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "limiter name is required"))
		return
	}
	req.Data.Name = name

	if registry.TrafficLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("limiter %s already exists", name)))
		return
	}

	v := parser.ParseTrafficLimiter(&req.Data)

	if err := registry.TrafficLimiterRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("limiter %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Limiters = append(c.Limiters, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateLimiterRequest
type updateLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"limiter" json:"limiter"`
	// in: body
	Data config.LimiterConfig `json:"data"`
}

// successful operation.
// swagger:response updateLimiterResponse
type updateLimiterResponse struct {
	Data Response
}

func updateLimiter(ctx *gin.Context) {
	// swagger:route PUT /config/limiters/{limiter} Limiter updateLimiterRequest
	//
	// Update limiter by name, the limiter must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateLimiterResponse

	var req updateLimiterRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Limiter)

	if !registry.TrafficLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("limiter %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseTrafficLimiter(&req.Data)

	registry.TrafficLimiterRegistry().Unregister(name)

	if err := registry.TrafficLimiterRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("limiter %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Limiters {
			if c.Limiters[i].Name == name {
				c.Limiters[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteLimiterRequest
type deleteLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"limiter" json:"limiter"`
}

// successful operation.
// swagger:response deleteLimiterResponse
type deleteLimiterResponse struct {
	Data Response
}

func deleteLimiter(ctx *gin.Context) {
	// swagger:route DELETE /config/limiters/{limiter} Limiter deleteLimiterRequest
	//
	// Delete limiter by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteLimiterResponse

	var req deleteLimiterRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Limiter)

	if !registry.TrafficLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("limiter %s not found", name)))
		return
	}
	registry.TrafficLimiterRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		limiteres := c.Limiters
		c.Limiters = nil
		for _, s := range limiteres {
			if s.Name == name {
				continue
			}
			c.Limiters = append(c.Limiters, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
