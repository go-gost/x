package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/router"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createRouterRequest
type createRouterRequest struct {
	// in: body
	Data config.RouterConfig `json:"data"`
}

// successful operation.
// swagger:response createRouterResponse
type createRouterResponse struct {
	Data Response
}

func createRouter(ctx *gin.Context) {
	// swagger:route POST /config/routers Router createRouterRequest
	//
	// Create a new router, the name of the router must be unique in router list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createRouterResponse

	var req createRouterRequest
	ctx.ShouldBindJSON(&req.Data)

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v := parser.ParseRouter(&req.Data)

	if err := registry.RouterRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Routers = append(c.Routers, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateRouterRequest
type updateRouterRequest struct {
	// in: path
	// required: true
	Router string `uri:"router" json:"router"`
	// in: body
	Data config.RouterConfig `json:"data"`
}

// successful operation.
// swagger:response updateRouterResponse
type updateRouterResponse struct {
	Data Response
}

func updateRouter(ctx *gin.Context) {
	// swagger:route PUT /config/routers/{router} Router updateRouterRequest
	//
	// Update router by name, the router must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateRouterResponse

	var req updateRouterRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	if !registry.RouterRegistry().IsRegistered(req.Router) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Router

	v := parser.ParseRouter(&req.Data)

	registry.RouterRegistry().Unregister(req.Router)

	if err := registry.RouterRegistry().Register(req.Router, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Routers {
			if c.Routers[i].Name == req.Router {
				c.Routers[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteRouterRequest
type deleteRouterRequest struct {
	// in: path
	// required: true
	Router string `uri:"router" json:"router"`
}

// successful operation.
// swagger:response deleteRouterResponse
type deleteRouterResponse struct {
	Data Response
}

func deleteRouter(ctx *gin.Context) {
	// swagger:route DELETE /config/routers/{router} Router deleteRouterRequest
	//
	// Delete router by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteRouterResponse

	var req deleteRouterRequest
	ctx.ShouldBindUri(&req)

	if !registry.RouterRegistry().IsRegistered(req.Router) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.RouterRegistry().Unregister(req.Router)

	config.OnUpdate(func(c *config.Config) error {
		routeres := c.Routers
		c.Routers = nil
		for _, s := range routeres {
			if s.Name == req.Router {
				continue
			}
			c.Routers = append(c.Routers, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
