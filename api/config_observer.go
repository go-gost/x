package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/observer"
	"github.com/go-gost/x/registry"
)

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

	if req.Data.Name == "" {
		writeError(ctx, ErrInvalid)
		return
	}

	v := parser.ParseObserver(&req.Data)

	if err := registry.ObserverRegistry().Register(req.Data.Name, v); err != nil {
		writeError(ctx, ErrDup)
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

	if !registry.ObserverRegistry().IsRegistered(req.Observer) {
		writeError(ctx, ErrNotFound)
		return
	}

	req.Data.Name = req.Observer

	v := parser.ParseObserver(&req.Data)

	registry.ObserverRegistry().Unregister(req.Observer)

	if err := registry.ObserverRegistry().Register(req.Observer, v); err != nil {
		writeError(ctx, ErrDup)
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Observers {
			if c.Observers[i].Name == req.Observer {
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

	if !registry.ObserverRegistry().IsRegistered(req.Observer) {
		writeError(ctx, ErrNotFound)
		return
	}
	registry.ObserverRegistry().Unregister(req.Observer)

	config.OnUpdate(func(c *config.Config) error {
		observers := c.Observers
		c.Observers = nil
		for _, s := range observers {
			if s.Name == req.Observer {
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
