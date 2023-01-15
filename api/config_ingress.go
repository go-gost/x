package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createIngressRequest
type createIngressRequest struct {
	// in: body
	Data config.IngressConfig `json:"data"`
}

// successful operation.
// swagger:response createIngressResponse
type createIngressResponse struct {
	Data Response
}

func createIngress(ctx *gin.Context) {
	// swagger:route POST /config/ingresses Ingress createIngressRequest
	//
	// Create a new ingress, the name of the ingress must be unique in ingress list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createIngressResponse

	var req createIngressRequest
	ctx.ShouldBindJSON(&req.Data)

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v := parsing.ParseIngress(&req.Data)

	if err := registry.IngressRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	cfg := config.Global()
	cfg.Ingresses = append(cfg.Ingresses, &req.Data)
	config.SetGlobal(cfg)

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateIngressRequest
type updateIngressRequest struct {
	// in: path
	// required: true
	Ingress string `uri:"ingress" json:"ingress"`
	// in: body
	Data config.IngressConfig `json:"data"`
}

// successful operation.
// swagger:response updateIngressResponse
type updateIngressResponse struct {
	Data Response
}

func updateIngress(ctx *gin.Context) {
	// swagger:route PUT /config/ingresses/{ingress} Ingress updateIngressRequest
	//
	// Update ingress by name, the ingress must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateIngressResponse

	var req updateIngressRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	if !registry.IngressRegistry().IsRegistered(req.Ingress) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Ingress

	v := parsing.ParseIngress(&req.Data)

	registry.IngressRegistry().Unregister(req.Ingress)

	if err := registry.IngressRegistry().Register(req.Ingress, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	cfg := config.Global()
	for i := range cfg.Ingresses {
		if cfg.Ingresses[i].Name == req.Ingress {
			cfg.Ingresses[i] = &req.Data
			break
		}
	}
	config.SetGlobal(cfg)

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteIngressRequest
type deleteIngressRequest struct {
	// in: path
	// required: true
	Ingress string `uri:"ingress" json:"ingress"`
}

// successful operation.
// swagger:response deleteIngressResponse
type deleteIngressResponse struct {
	Data Response
}

func deleteIngress(ctx *gin.Context) {
	// swagger:route DELETE /config/ingresses/{ingress} Ingress deleteIngressRequest
	//
	// Delete ingress by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteIngressResponse

	var req deleteIngressRequest
	ctx.ShouldBindUri(&req)

	if !registry.IngressRegistry().IsRegistered(req.Ingress) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.IngressRegistry().Unregister(req.Ingress)

	cfg := config.Global()
	ingresses := cfg.Ingresses
	cfg.Ingresses = nil
	for _, s := range ingresses {
		if s.Name == req.Ingress {
			continue
		}
		cfg.Ingresses = append(cfg.Ingresses, s)
	}
	config.SetGlobal(cfg)

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
