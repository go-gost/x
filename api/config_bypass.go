package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createBypassRequest
type createBypassRequest struct {
	// in: body
	Data config.BypassConfig `json:"data"`
}

// successful operation.
// swagger:response createBypassResponse
type createBypassResponse struct {
	Data Response
}

func createBypass(ctx *gin.Context) {
	// swagger:route POST /config/bypasses Bypass createBypassRequest
	//
	// Create a new bypass, the name of bypass must be unique in bypass list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createBypassResponse

	var req createBypassRequest
	ctx.ShouldBindJSON(&req.Data)

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v := parsing.ParseBypass(&req.Data)

	if err := registry.BypassRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Bypasses = append(c.Bypasses, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateBypassRequest
type updateBypassRequest struct {
	// in: path
	// required: true
	Bypass string `uri:"bypass" json:"bypass"`
	// in: body
	Data config.BypassConfig `json:"data"`
}

// successful operation.
// swagger:response updateBypassResponse
type updateBypassResponse struct {
	Data Response
}

func updateBypass(ctx *gin.Context) {
	// swagger:route PUT /config/bypasses/{bypass} Bypass updateBypassRequest
	//
	// Update bypass by name, the bypass must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateBypassResponse

	var req updateBypassRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	if !registry.BypassRegistry().IsRegistered(req.Bypass) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Bypass

	v := parsing.ParseBypass(&req.Data)

	registry.BypassRegistry().Unregister(req.Bypass)

	if err := registry.BypassRegistry().Register(req.Bypass, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Bypasses {
			if c.Bypasses[i].Name == req.Bypass {
				c.Bypasses[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteBypassRequest
type deleteBypassRequest struct {
	// in: path
	// required: true
	Bypass string `uri:"bypass" json:"bypass"`
}

// successful operation.
// swagger:response deleteBypassResponse
type deleteBypassResponse struct {
	Data Response
}

func deleteBypass(ctx *gin.Context) {
	// swagger:route DELETE /config/bypasses/{bypass} Bypass deleteBypassRequest
	//
	// Delete bypass by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteBypassResponse

	var req deleteBypassRequest
	ctx.ShouldBindUri(&req)

	if !registry.BypassRegistry().IsRegistered(req.Bypass) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.BypassRegistry().Unregister(req.Bypass)

	config.OnUpdate(func(c *config.Config) error {
		bypasses := c.Bypasses
		c.Bypasses = nil
		for _, s := range bypasses {
			if s.Name == req.Bypass {
				continue
			}
			c.Bypasses = append(c.Bypasses, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
