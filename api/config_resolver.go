package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/resolver"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createResolverRequest
type createResolverRequest struct {
	// in: body
	Data config.ResolverConfig `json:"data"`
}

// successful operation.
// swagger:response createResolverResponse
type createResolverResponse struct {
	Data Response
}

func createResolver(ctx *gin.Context) {
	// swagger:route POST /config/resolvers Resolver createResolverRequest
	//
	// Create a new resolver, the name of the resolver must be unique in resolver list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createResolverResponse

	var req createResolverRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "resolver name is required"))
		return
	}
	req.Data.Name = name

	if registry.ResolverRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("resolver %s already exists", name)))
		return
	}

	v, err := parser.ParseResolver(&req.Data)
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create resolver %s failed: %s", name, err.Error())))
		return
	}

	if err := registry.ResolverRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("resolver %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Resolvers = append(c.Resolvers, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateResolverRequest
type updateResolverRequest struct {
	// in: path
	// required: true
	Resolver string `uri:"resolver" json:"resolver"`
	// in: body
	Data config.ResolverConfig `json:"data"`
}

// successful operation.
// swagger:response updateResolverResponse
type updateResolverResponse struct {
	Data Response
}

func updateResolver(ctx *gin.Context) {
	// swagger:route PUT /config/resolvers/{resolver} Resolver updateResolverRequest
	//
	// Update resolver by name, the resolver must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateResolverResponse

	var req updateResolverRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Resolver)

	if !registry.ResolverRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("resolver %s not found", name)))
		return
	}

	req.Data.Name = name

	v, err := parser.ParseResolver(&req.Data)
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create resolver %s failed: %s", name, err.Error())))
		return
	}

	registry.ResolverRegistry().Unregister(name)

	if err := registry.ResolverRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("resolver %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Resolvers {
			if c.Resolvers[i].Name == name {
				c.Resolvers[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteResolverRequest
type deleteResolverRequest struct {
	// in: path
	// required: true
	Resolver string `uri:"resolver" json:"resolver"`
}

// successful operation.
// swagger:response deleteResolverResponse
type deleteResolverResponse struct {
	Data Response
}

func deleteResolver(ctx *gin.Context) {
	// swagger:route DELETE /config/resolvers/{resolver} Resolver deleteResolverRequest
	//
	// Delete resolver by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteResolverResponse

	var req deleteResolverRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Resolver)

	if !registry.ResolverRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("resolver %s not found", name)))
		return
	}
	registry.ResolverRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		resolvers := c.Resolvers
		c.Resolvers = nil
		for _, s := range resolvers {
			if s.Name == name {
				continue
			}
			c.Resolvers = append(c.Resolvers, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
