package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createConnLimiterRequest
type createConnLimiterRequest struct {
	// in: body
	Data config.LimiterConfig `json:"data"`
}

// successful operation.
// swagger:response createConnLimiterResponse
type createConnLimiterResponse struct {
	Data Response
}

func createConnLimiter(ctx *gin.Context) {
	// swagger:route POST /config/climiters Limiter createConnLimiterRequest
	//
	// Create a new conn limiter, the name of limiter must be unique in limiter list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createConnLimiterResponse

	var req createConnLimiterRequest
	ctx.ShouldBindJSON(&req.Data)

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v := parsing.ParseConnLimiter(&req.Data)

	if err := registry.ConnLimiterRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	cfg := config.Global()
	cfg.CLimiters = append(cfg.CLimiters, &req.Data)
	config.SetGlobal(cfg)

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateConnLimiterRequest
type updateConnLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"limiter" json:"limiter"`
	// in: body
	Data config.LimiterConfig `json:"data"`
}

// successful operation.
// swagger:response updateConnLimiterResponse
type updateConnLimiterResponse struct {
	Data Response
}

func updateConnLimiter(ctx *gin.Context) {
	// swagger:route PUT /config/climiters/{limiter} Limiter updateConnLimiterRequest
	//
	// Update conn limiter by name, the limiter must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateConnLimiterResponse

	var req updateConnLimiterRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	if !registry.ConnLimiterRegistry().IsRegistered(req.Limiter) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Limiter

	v := parsing.ParseConnLimiter(&req.Data)

	registry.ConnLimiterRegistry().Unregister(req.Limiter)

	if err := registry.ConnLimiterRegistry().Register(req.Limiter, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	cfg := config.Global()
	for i := range cfg.Limiters {
		if cfg.Limiters[i].Name == req.Limiter {
			cfg.Limiters[i] = &req.Data
			break
		}
	}
	config.SetGlobal(cfg)

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteConnLimiterRequest
type deleteConnLimiterRequest struct {
	// in: path
	// required: true
	Limiter string `uri:"Limiter" json:"Limiter"`
}

// successful operation.
// swagger:response deleteConnLimiterResponse
type deleteConnLimiterResponse struct {
	Data Response
}

func deleteConnLimiter(ctx *gin.Context) {
	// swagger:route DELETE /config/climiters/{limiter} Limiter deleteConnLimiterRequest
	//
	// Delete conn limiter by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteConnLimiterResponse

	var req deleteConnLimiterRequest
	ctx.ShouldBindUri(&req)

	if !registry.ConnLimiterRegistry().IsRegistered(req.Limiter) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.ConnLimiterRegistry().Unregister(req.Limiter)

	cfg := config.Global()
	limiteres := cfg.Limiters
	cfg.Limiters = nil
	for _, s := range limiteres {
		if s.Name == req.Limiter {
			continue
		}
		cfg.Limiters = append(cfg.Limiters, s)
	}
	config.SetGlobal(cfg)

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
