package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/auth"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createAutherRequest
type createAutherRequest struct {
	// in: body
	Data config.AutherConfig `json:"data"`
}

// successful operation.
// swagger:response createAutherResponse
type createAutherResponse struct {
	Data Response
}

func createAuther(ctx *gin.Context) {
	// swagger:route POST /config/authers Auther createAutherRequest
	//
	// Create a new auther, the name of the auther must be unique in auther list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createAutherResponse

	var req createAutherRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "auther name is required"))
		return
	}
	req.Data.Name = name

	if registry.AutherRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("auther %s already exists", name)))
		return
	}

	v := parser.ParseAuther(&req.Data)
	if err := registry.AutherRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("auther %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Authers = append(c.Authers, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateAutherRequest
type updateAutherRequest struct {
	// in: path
	// required: true
	Auther string `uri:"auther" json:"auther"`
	// in: body
	Data config.AutherConfig `json:"data"`
}

// successful operation.
// swagger:response updateAutherResponse
type updateAutherResponse struct {
	Data Response
}

func updateAuther(ctx *gin.Context) {
	// swagger:route PUT /config/authers/{auther} Auther updateAutherRequest
	//
	// Update auther by name, the auther must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateAutherResponse

	var req updateAutherRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Auther)

	if !registry.AutherRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("auther %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseAuther(&req.Data)
	registry.AutherRegistry().Unregister(name)

	if err := registry.AutherRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("auther %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Authers {
			if c.Authers[i].Name == name {
				c.Authers[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteAutherRequest
type deleteAutherRequest struct {
	// in: path
	// required: true
	Auther string `uri:"auther" json:"auther"`
}

// successful operation.
// swagger:response deleteAutherResponse
type deleteAutherResponse struct {
	Data Response
}

func deleteAuther(ctx *gin.Context) {
	// swagger:route DELETE /config/authers/{auther} Auther deleteAutherRequest
	//
	// Delete auther by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteAutherResponse

	var req deleteAutherRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Auther)

	if !registry.AutherRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("auther %s not found", name)))
		return
	}
	registry.AutherRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		authers := c.Authers
		c.Authers = nil
		for _, s := range authers {
			if s.Name == name {
				continue
			}
			c.Authers = append(c.Authers, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
