package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/recorder"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createRecorderRequest
type createRecorderRequest struct {
	// in: body
	Data config.RecorderConfig `json:"data"`
}

// successful operation.
// swagger:response createRecorderResponse
type createRecorderResponse struct {
	Data Response
}

func createRecorder(ctx *gin.Context) {
	// swagger:route POST /config/recorders Recorder createRecorderRequest
	//
	// Create a new recorder, the name of the recorder must be unique in recorder list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createRecorderResponse

	var req createRecorderRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "recorder name is required"))
		return
	}
	req.Data.Name = name

	if registry.RecorderRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("recorder %s already exists", name)))
		return
	}
	v := parser.ParseRecorder(&req.Data)

	if err := registry.RecorderRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("recorder %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Recorders = append(c.Recorders, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateRecorderRequest
type updateRecorderRequest struct {
	// in: path
	// required: true
	Recorder string `uri:"recorder" json:"recorder"`
	// in: body
	Data config.RecorderConfig `json:"data"`
}

// successful operation.
// swagger:response updateRecorderResponse
type updateRecorderResponse struct {
	Data Response
}

func updateRecorder(ctx *gin.Context) {
	// swagger:route PUT /config/recorders/{recorder} Recorder updateRecorderRequest
	//
	// Update recorder by name, the recorder must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateRecorderResponse

	var req updateRecorderRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Recorder)

	if !registry.RecorderRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("recorder %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseRecorder(&req.Data)

	registry.RecorderRegistry().Unregister(name)

	if err := registry.RecorderRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("recorder %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Recorders {
			if c.Recorders[i].Name == name {
				c.Recorders[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteRecorderRequest
type deleteRecorderRequest struct {
	// in: path
	// required: true
	Recorder string `uri:"recorder" json:"recorder"`
}

// successful operation.
// swagger:response deleteRecorderResponse
type deleteRecorderResponse struct {
	Data Response
}

func deleteRecorder(ctx *gin.Context) {
	// swagger:route DELETE /config/recorders/{recorder} Recorder deleteRecorderRequest
	//
	// Delete recorder by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteRecorderResponse

	var req deleteRecorderRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Recorder)

	if !registry.RecorderRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("recorder %s not found", name)))
		return
	}
	registry.RecorderRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		recorders := c.Recorders
		c.Recorders = nil
		for _, s := range recorders {
			if s.Name == name {
				continue
			}
			c.Recorders = append(c.Recorders, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
