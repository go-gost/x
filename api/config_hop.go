package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
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

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v, err := parsing.ParseHop(&req.Data)
	if err != nil {
		writeError(ctx, ErrCreate)
		return
	}

	if err := registry.HopRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
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

	if !registry.HopRegistry().IsRegistered(req.Hop) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Hop

	v, err := parsing.ParseHop(&req.Data)
	if err != nil {
		writeError(ctx, ErrCreate)
		return
	}

	registry.HopRegistry().Unregister(req.Hop)

	if err := registry.HopRegistry().Register(req.Hop, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Hops {
			if c.Hops[i].Name == req.Hop {
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

	if !registry.HopRegistry().IsRegistered(req.Hop) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.HopRegistry().Unregister(req.Hop)

	config.OnUpdate(func(c *config.Config) error {
		hops := c.Hops
		c.Hops = nil
		for _, s := range hops {
			if s.Name == req.Hop {
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
