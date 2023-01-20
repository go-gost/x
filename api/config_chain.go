package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
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

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v, err := parsing.ParseChain(&req.Data)
	if err != nil {
		writeError(ctx, ErrCreate)
		return
	}

	if err := registry.ChainRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
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

	if !registry.ChainRegistry().IsRegistered(req.Chain) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Chain

	v, err := parsing.ParseChain(&req.Data)
	if err != nil {
		writeError(ctx, ErrCreate)
		return
	}

	registry.ChainRegistry().Unregister(req.Chain)

	if err := registry.ChainRegistry().Register(req.Chain, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Chains {
			if c.Chains[i].Name == req.Chain {
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

	if !registry.ChainRegistry().IsRegistered(req.Chain) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.ChainRegistry().Unregister(req.Chain)

	config.OnUpdate(func(c *config.Config) error {
		chains := c.Chains
		c.Chains = nil
		for _, s := range chains {
			if s.Name == req.Chain {
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
