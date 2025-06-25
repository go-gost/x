package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/observer"
	"github.com/go-gost/x/registry"
)

// swagger:parameters getObserverListRequest
type getObserverListRequest struct {
}

// successful operation.
// swagger:response getObserverListResponse
type getObserverListResponse struct {
	// in: body
	Data observerList
}

type observerList struct {
	Count int                       `json:"count"`
	List  []*config.ObserverConfig `json:"list"`
}

func getObserverList(ctx *gin.Context) {
	// swagger:route GET /config/observers Observer getObserverListRequest
	//
	// Get observer list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getObserverListResponse

	var req getObserverListRequest
	ctx.ShouldBindQuery(&req)

	list := config.Global().Observers

	var resp getObserverListResponse
	resp.Data = observerList{
		Count: len(list),
		List:  list,
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters getObserverRequest
type getObserverRequest struct {
	// in: path
	// required: true
	Observer string `uri:"observer" json:"observer"`
}

// successful operation.
// swagger:response getObserverResponse
type getObserverResponse struct {
	// in: body
	Data *config.ObserverConfig
}

func getObserver(ctx *gin.Context) {
	// swagger:route GET /config/observers/{observer} Observer getObserverRequest
	//
	// Get observer.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getObserverResponse

	var req getObserverRequest
	ctx.ShouldBindUri(&req)

	var resp getObserverResponse

	for _, observer := range config.Global().Observers {
		if observer == nil {
			continue
		}
		if observer.Name == req.Observer {
			resp.Data = observer
		}
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters createObserverRequest
type createObserverRequest struct {
	// in: body
	Data config.ObserverConfig `json:"data"`
}

// successful operation.
// swagger:response createObserverResponse
type createObserverResponse struct {
	Data Response
}

func createObserver(ctx *gin.Context) {
	// swagger:route POST /config/observers Observer createObserverRequest
	//
	// Create a new observer, the name of the observer must be unique in observer list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createObserverResponse

	var req createObserverRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "observer name is required"))
		return
	}
	req.Data.Name = name

	if registry.ObserverRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("observer %s already exists", name)))
		return
	}

	v := parser.ParseObserver(&req.Data)

	if err := registry.ObserverRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("observer %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Observers = append(c.Observers, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateObserverRequest
type updateObserverRequest struct {
	// in: path
	// required: true
	Observer string `uri:"observer" json:"observer"`
	// in: body
	Data config.ObserverConfig `json:"data"`
}

// successful operation.
// swagger:response updateObserverResponse
type updateObserverResponse struct {
	Data Response
}

func updateObserver(ctx *gin.Context) {
	// swagger:route PUT /config/observers/{observer} Observer updateObserverRequest
	//
	// Update observer by name, the observer must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateObserverResponse

	var req updateObserverRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Observer)

	if !registry.ObserverRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("observer %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseObserver(&req.Data)

	registry.ObserverRegistry().Unregister(name)

	if err := registry.ObserverRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("observer %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Observers {
			if c.Observers[i].Name == name {
				c.Observers[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteObserverRequest
type deleteObserverRequest struct {
	// in: path
	// required: true
	Observer string `uri:"observer" json:"observer"`
}

// successful operation.
// swagger:response deleteObserverResponse
type deleteObserverResponse struct {
	Data Response
}

func deleteObserver(ctx *gin.Context) {
	// swagger:route DELETE /config/observers/{observer} Observer deleteObserverRequest
	//
	// Delete observer by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteObserverResponse

	var req deleteObserverRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Observer)

	if !registry.ObserverRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("observer %s not found", name)))
		return
	}
	registry.ObserverRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		observers := c.Observers
		c.Observers = nil
		for _, s := range observers {
			if s.Name == name {
				continue
			}
			c.Observers = append(c.Observers, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
