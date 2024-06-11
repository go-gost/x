package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/hop"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createHopRequest
type createHopRequest struct {
	// in: body
	Data config.HopConfig `json:"data"`
}

// successful operation.
// swagger:response createHopResponse
type createHopResponse struct {
	Data Response
}

func createHop(ctx *gin.Context) {
	// swagger:route POST /config/hops Hop createHopRequest
	//
	// Create a new hop, the name of hop must be unique in hop list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createHopResponse

	var req createHopRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "hop name is required"))
		return
	}
	req.Data.Name = name

	if registry.HopRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("hop %s already exists", name)))
		return
	}

	v, err := parser.ParseHop(&req.Data, logger.Default())
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create hop %s failed: %s", name, err.Error())))
		return
	}

	if err := registry.HopRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("hop %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Hops = append(c.Hops, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateHopRequest
type updateHopRequest struct {
	// in: path
	// required: true
	// hop name
	Hop string `uri:"hop" json:"hop"`
	// in: body
	Data config.HopConfig `json:"data"`
}

// successful operation.
// swagger:response updateHopResponse
type updateHopResponse struct {
	Data Response
}

func updateHop(ctx *gin.Context) {
	// swagger:route PUT /config/hops/{hop} Hop updateHopRequest
	//
	// Update hop by name, the hop must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateHopResponse

	var req updateHopRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Hop)
	if !registry.HopRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("hop %s not found", name)))
		return
	}

	req.Data.Name = name

	v, err := parser.ParseHop(&req.Data, logger.Default())
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create hop %s failed: %s", name, err.Error())))
		return
	}

	registry.HopRegistry().Unregister(name)

	if err := registry.HopRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("hop %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Hops {
			if c.Hops[i].Name == name {
				c.Hops[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteHopRequest
type deleteHopRequest struct {
	// in: path
	// required: true
	Hop string `uri:"hop" json:"hop"`
}

// successful operation.
// swagger:response deleteHopResponse
type deleteHopResponse struct {
	Data Response
}

func deleteHop(ctx *gin.Context) {
	// swagger:route DELETE /config/hops/{hop} Hop deleteHopRequest
	//
	// Delete hop by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteHopResponse

	var req deleteHopRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Hop)

	if !registry.HopRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("hop %s not found", name)))
		return
	}
	registry.HopRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		hops := c.Hops
		c.Hops = nil
		for _, s := range hops {
			if s.Name == name {
				continue
			}
			c.Hops = append(c.Hops, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
