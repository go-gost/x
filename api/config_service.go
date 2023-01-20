package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createServiceRequest
type createServiceRequest struct {
	// in: body
	Data config.ServiceConfig `json:"data"`
}

// successful operation.
// swagger:response createServiceResponse
type createServiceResponse struct {
	Data Response
}

func createService(ctx *gin.Context) {
	// swagger:route POST /config/services Service createServiceRequest
	//
	// Create a new service, the name of the service must be unique in service list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createServiceResponse

	var req createServiceRequest
	ctx.ShouldBindJSON(&req.Data)

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	if registry.ServiceRegistry().IsRegistered(req.Data.Name) {
		writeError(ctx, ErrDup)
		return
	}

	svc, err := parsing.ParseService(&req.Data)
	if err != nil {
		writeError(ctx, ErrCreate)
		return
	}

	if err := registry.ServiceRegistry().Register(req.Data.Name, svc); err != nil {
		svc.Close()
		writeError(ctx, ErrDup)
		return
	}

	go svc.Serve()

	config.OnUpdate(func(c *config.Config) error {
		c.Services = append(c.Services, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateServiceRequest
type updateServiceRequest struct {
	// in: path
	// required: true
	Service string `uri:"service" json:"service"`
	// in: body
	Data config.ServiceConfig `json:"data"`
}

// successful operation.
// swagger:response updateServiceResponse
type updateServiceResponse struct {
	Data Response
}

func updateService(ctx *gin.Context) {
	// swagger:route PUT /config/services/{service} Service updateServiceRequest
	//
	// Update service by name, the service must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateServiceResponse

	var req updateServiceRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	old := registry.ServiceRegistry().Get(req.Service)
	if old == nil {
		writeError(ctx, ErrNotFound)
		return
	}
	old.Close()

	req.Data.Name = req.Service

	svc, err := parsing.ParseService(&req.Data)
	if err != nil {
		writeError(ctx, ErrCreate)
		return
	}

	registry.ServiceRegistry().Unregister(req.Service)

	if err := registry.ServiceRegistry().Register(req.Service, svc); err != nil {
		svc.Close()
		writeError(ctx, ErrDup)
		return
	}

	go svc.Serve()

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Services {
			if c.Services[i].Name == req.Service {
				c.Services[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteServiceRequest
type deleteServiceRequest struct {
	// in: path
	// required: true
	Service string `uri:"service" json:"service"`
}

// successful operation.
// swagger:response deleteServiceResponse
type deleteServiceResponse struct {
	Data Response
}

func deleteService(ctx *gin.Context) {
	// swagger:route DELETE /config/services/{service} Service deleteServiceRequest
	//
	// Delete service by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteServiceResponse

	var req deleteServiceRequest
	ctx.ShouldBindUri(&req)

	svc := registry.ServiceRegistry().Get(req.Service)
	if svc == nil {
		writeError(ctx, ErrNotFound)
		return
	}

	registry.ServiceRegistry().Unregister(req.Service)
	svc.Close()

	config.OnUpdate(func(c *config.Config) error {
		services := c.Services
		c.Services = nil
		for _, s := range services {
			if s.Name == req.Service {
				continue
			}
			c.Services = append(c.Services, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
