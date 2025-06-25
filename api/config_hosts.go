package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/hosts"
	"github.com/go-gost/x/registry"
)

// swagger:parameters getHostsListRequest
type getHostsListRequest struct {
}

// successful operation.
// swagger:response getHostsListResponse
type getHostsListResponse struct {
	// in: body
	Data hostsList
}

type hostsList struct {
	Count int                   `json:"count"`
	List  []*config.HostsConfig `json:"list"`
}

func getHostsList(ctx *gin.Context) {
	// swagger:route GET /config/hosts Hosts getHostsListRequest
	//
	// Get hosts list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getHostsListResponse

	var req getHostsListRequest
	ctx.ShouldBindQuery(&req)

	list := config.Global().Hosts

	var resp getHostsListResponse
	resp.Data = hostsList{
		Count: len(list),
		List:  list,
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters getHostsRequest
type getHostsRequest struct {
	// in: path
	// required: true
	Hosts string `uri:"hosts" json:"hosts"`
}

// successful operation.
// swagger:response getHostsResponse
type getHostsResponse struct {
	// in: body
	Data *config.HostsConfig
}

func getHosts(ctx *gin.Context) {
	// swagger:route GET /config/hosts/{hosts} Hosts getHostsRequest
	//
	// Get hosts.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getHostsResponse

	var req getHostsRequest
	ctx.ShouldBindUri(&req)

	var resp getHostsResponse

	for _, hosts := range config.Global().Hosts {
		if hosts == nil {
			continue
		}
		if hosts.Name == req.Hosts {
			resp.Data = hosts
		}
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters createHostsRequest
type createHostsRequest struct {
	// in: body
	Data config.HostsConfig `json:"data"`
}

// successful operation.
// swagger:response createHostsResponse
type createHostsesponse struct {
	Data Response
}

func createHosts(ctx *gin.Context) {
	// swagger:route POST /config/hosts Hosts createHostsRequest
	//
	// Create a new hosts, the name of the hosts must be unique in hosts list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createHostsResponse

	var req createHostsRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "hosts name is required"))
		return
	}
	req.Data.Name = name

	if registry.HostsRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("hosts %s already exists", name)))
		return
	}

	v := parser.ParseHostMapper(&req.Data)

	if err := registry.HostsRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("hosts %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Hosts = append(c.Hosts, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateHostsRequest
type updateHostsRequest struct {
	// in: path
	// required: true
	Hosts string `uri:"hosts" json:"hosts"`
	// in: body
	Data config.HostsConfig `json:"data"`
}

// successful operation.
// swagger:response updateHostsResponse
type updateHostsResponse struct {
	Data Response
}

func updateHosts(ctx *gin.Context) {
	// swagger:route PUT /config/hosts/{hosts} Hosts updateHostsRequest
	//
	// Update hosts by name, the hosts must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateHostsResponse

	var req updateHostsRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Hosts)

	if !registry.HostsRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("hosts %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseHostMapper(&req.Data)

	registry.HostsRegistry().Unregister(name)

	if err := registry.HostsRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("hosts %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Hosts {
			if c.Hosts[i].Name == name {
				c.Hosts[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteHostsRequest
type deleteHostsRequest struct {
	// in: path
	// required: true
	Hosts string `uri:"hosts" json:"hosts"`
}

// successful operation.
// swagger:response deleteHostsResponse
type deleteHostsResponse struct {
	Data Response
}

func deleteHosts(ctx *gin.Context) {
	// swagger:route DELETE /config/hosts/{hosts} Hosts deleteHostsRequest
	//
	// Delete hosts by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteHostsResponse

	var req deleteHostsRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Hosts)

	if !registry.HostsRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("hosts %s not found", name)))
		return
	}
	registry.HostsRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		hosts := c.Hosts
		c.Hosts = nil
		for _, s := range hosts {
			if s.Name == name {
				continue
			}
			c.Hosts = append(c.Hosts, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
