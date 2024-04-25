package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/sd"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createSDRequest
type createSDRequest struct {
	// in: body
	Data config.SDConfig `json:"data"`
}

// successful operation.
// swagger:response createSDResponse
type createSDResponse struct {
	Data Response
}

func createSD(ctx *gin.Context) {
	// swagger:route POST /config/sds SD createSDRequest
	//
	// Create a new SD, the name of the SD must be unique in SD list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createSDResponse

	var req createSDRequest
	ctx.ShouldBindJSON(&req.Data)

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v := parser.ParseSD(&req.Data)

	if err := registry.SDRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.SDs = append(c.SDs, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateSDRequest
type updateSDRequest struct {
	// in: path
	// required: true
	SD string `uri:"sd" json:"sd"`
	// in: body
	Data config.SDConfig `json:"data"`
}

// successful operation.
// swagger:response updateSDResponse
type updateSDResponse struct {
	Data Response
}

func updateSD(ctx *gin.Context) {
	// swagger:route PUT /config/sds/{sd} SD updateSDRequest
	//
	// Update SD by name, the SD must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateSDResponse

	var req updateSDRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	if !registry.SDRegistry().IsRegistered(req.SD) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.SD

	v := parser.ParseSD(&req.Data)

	registry.SDRegistry().Unregister(req.SD)

	if err := registry.SDRegistry().Register(req.SD, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.SDs {
			if c.SDs[i].Name == req.SD {
				c.SDs[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteSDRequest
type deleteSDRequest struct {
	// in: path
	// required: true
	SD string `uri:"sd" json:"sd"`
}

// successful operation.
// swagger:response deleteSDResponse
type deleteSDResponse struct {
	Data Response
}

func deleteSD(ctx *gin.Context) {
	// swagger:route DELETE /config/sds/{sd} SD deleteSDRequest
	//
	// Delete SD by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteSDResponse

	var req deleteSDRequest
	ctx.ShouldBindUri(&req)

	if !registry.SDRegistry().IsRegistered(req.SD) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.SDRegistry().Unregister(req.SD)

	config.OnUpdate(func(c *config.Config) error {
		sds := c.SDs
		c.SDs = nil
		for _, s := range sds {
			if s.Name == req.SD {
				continue
			}
			c.SDs = append(c.SDs, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
