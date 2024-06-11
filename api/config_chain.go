package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/chain"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createChainRequest
type createChainRequest struct {
	// in: body
	Data config.ChainConfig `json:"data"`
}

// successful operation.
// swagger:response createChainResponse
type createChainResponse struct {
	Data Response
}

func createChain(ctx *gin.Context) {
	// swagger:route POST /config/chains Chain createChainRequest
	//
	// Create a new chain, the name of chain must be unique in chain list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createChainResponse

	var req createChainRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "chain name is required"))
		return
	}
	req.Data.Name = name

	if registry.ChainRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("chain %s already exists", name)))
		return
	}

	v, err := parser.ParseChain(&req.Data, logger.Default())
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create chain %s failed: %s", name, err.Error())))
		return
	}

	if err := registry.ChainRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("chain %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Chains = append(c.Chains, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateChainRequest
type updateChainRequest struct {
	// in: path
	// required: true
	// chain name
	Chain string `uri:"chain" json:"chain"`
	// in: body
	Data config.ChainConfig `json:"data"`
}

// successful operation.
// swagger:response updateChainResponse
type updateChainResponse struct {
	Data Response
}

func updateChain(ctx *gin.Context) {
	// swagger:route PUT /config/chains/{chain} Chain updateChainRequest
	//
	// Update chain by name, the chain must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateChainResponse

	var req updateChainRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Chain)

	if !registry.ChainRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("chain %s not found", name)))
		return
	}

	req.Data.Name = name

	v, err := parser.ParseChain(&req.Data, logger.Default())
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create chain %s failed: %s", name, err.Error())))
		return
	}

	registry.ChainRegistry().Unregister(name)

	if err := registry.ChainRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("chain %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Chains {
			if c.Chains[i].Name == name {
				c.Chains[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteChainRequest
type deleteChainRequest struct {
	// in: path
	// required: true
	Chain string `uri:"chain" json:"chain"`
}

// successful operation.
// swagger:response deleteChainResponse
type deleteChainResponse struct {
	Data Response
}

func deleteChain(ctx *gin.Context) {
	// swagger:route DELETE /config/chains/{chain} Chain deleteChainRequest
	//
	// Delete chain by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteChainResponse

	var req deleteChainRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Chain)

	if !registry.ChainRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("chain %s not found", name)))
		return
	}
	registry.ChainRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		chains := c.Chains
		c.Chains = nil
		for _, s := range chains {
			if s.Name == name {
				continue
			}
			c.Chains = append(c.Chains, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
