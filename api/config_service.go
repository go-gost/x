package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/service"
	"github.com/go-gost/x/registry"
)

// swagger:parameters getServiceListRequest
type getServiceListRequest struct {
}

// successful operation.
// swagger:response getServiceListResponse
type getServiceListResponse struct {
	// in: body
	Data serviceList
}

type serviceList struct {
	Count int                       `json:"count"`
	List  []*config.ServiceConfig `json:"list"`
}

func getServiceList(ctx *gin.Context) {
	// swagger:route GET /config/services Service getServiceListRequest
	//
	// Get service list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getServiceListResponse

	var req getServiceListRequest
	ctx.ShouldBindQuery(&req)

	list := config.Global().Services

	var resp getServiceListResponse
	resp.Data = serviceList{
		Count: len(list),
		List:  list,
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters getServiceRequest
type getServiceRequest struct {
	// in: path
	// required: true
	Service string `uri:"service" json:"service"`
}

// successful operation.
// swagger:response getServiceResponse
type getServiceResponse struct {
	// in: body
	Data *config.ServiceConfig
}

func getService(ctx *gin.Context) {
	// swagger:route GET /config/services/{service} Service getServiceRequest
	//
	// Get service.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getServiceResponse

	var req getServiceRequest
	ctx.ShouldBindUri(&req)

	var resp getServiceResponse

	for _, service := range config.Global().Services {
		if service == nil {
			continue
		}
		if service.Name == req.Service {
			resp.Data = service
		}
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

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

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "service name is required"))
		return
	}
	req.Data.Name = name

	if registry.ServiceRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("service %s already exists", name)))
		return
	}

	svc, err := parser.ParseService(&req.Data)
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create service %s failed: %s", name, err.Error())))
		return
	}

	if err := registry.ServiceRegistry().Register(name, svc); err != nil {
		svc.Close()
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("service %s already exists", name)))
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

	name := strings.TrimSpace(req.Service)

	old := registry.ServiceRegistry().Get(name)
	if old == nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("service %s not found", name)))
		return
	}
	old.Close()

	req.Data.Name = name

	svc, err := parser.ParseService(&req.Data)
	if err != nil {
		writeError(ctx, NewError(http.StatusInternalServerError, ErrCodeFailed, fmt.Sprintf("create service %s failed: %s", name, err.Error())))
		return
	}

	registry.ServiceRegistry().Unregister(name)

	if err := registry.ServiceRegistry().Register(name, svc); err != nil {
		svc.Close()
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("service %s already exists", name)))
		return
	}

	go svc.Serve()

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Services {
			if c.Services[i].Name == name {
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

	name := strings.TrimSpace(req.Service)

	svc := registry.ServiceRegistry().Get(name)
	if svc == nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("service %s not found", name)))
		return
	}

	registry.ServiceRegistry().Unregister(name)
	svc.Close()

	config.OnUpdate(func(c *config.Config) error {
		services := c.Services
		c.Services = nil
		for _, s := range services {
			if s.Name == name {
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
