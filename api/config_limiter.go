package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	"github.com/go-gost/x/registry"
)

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

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v := parsing.ParseTrafficLimiter(&req.Data)

	if err := registry.TrafficLimiterRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
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

	if !registry.TrafficLimiterRegistry().IsRegistered(req.Limiter) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Limiter

	v := parsing.ParseTrafficLimiter(&req.Data)

	registry.TrafficLimiterRegistry().Unregister(req.Limiter)

	if err := registry.TrafficLimiterRegistry().Register(req.Limiter, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Limiters {
			if c.Limiters[i].Name == req.Limiter {
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

	if !registry.TrafficLimiterRegistry().IsRegistered(req.Limiter) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.TrafficLimiterRegistry().Unregister(req.Limiter)

	config.OnUpdate(func(c *config.Config) error {
		limiteres := c.Limiters
		c.Limiters = nil
		for _, s := range limiteres {
			if s.Name == req.Limiter {
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
