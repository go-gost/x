package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/admission"
	"github.com/go-gost/x/registry"
)

// swagger:parameters createAdmissionRequest
type createAdmissionRequest struct {
	// in: body
	Data config.AdmissionConfig `json:"data"`
}

// successful operation.
// swagger:response createAdmissionResponse
type createAdmissionResponse struct {
	Data Response
}

func createAdmission(ctx *gin.Context) {
	// swagger:route POST /config/admissions Admission createAdmissionRequest
	//
	// Create a new admission, the name of admission must be unique in admission list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createAdmissionResponse

	var req createAdmissionRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "admission name is required"))
		return
	}
	req.Data.Name = name

	if registry.AdmissionRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("admission %s already exists", name)))
		return
	}

	v := parser.ParseAdmission(&req.Data)

	if err := registry.AdmissionRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("admission %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Admissions = append(c.Admissions, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateAdmissionRequest
type updateAdmissionRequest struct {
	// in: path
	// required: true
	Admission string `uri:"admission" json:"admission"`
	// in: body
	Data config.AdmissionConfig `json:"data"`
}

// successful operation.
// swagger:response updateAdmissionResponse
type updateAdmissionResponse struct {
	Data Response
}

func updateAdmission(ctx *gin.Context) {
	// swagger:route PUT /config/admissions/{admission} Admission updateAdmissionRequest
	//
	// Update admission by name, the admission must already exist.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateAdmissionResponse

	var req updateAdmissionRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Admission)

	if !registry.AdmissionRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("admission %s not found", name)))
		return
	}

	req.Data.Name = name

	v := parser.ParseAdmission(&req.Data)

	registry.AdmissionRegistry().Unregister(name)

	if err := registry.AdmissionRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("admission %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Admissions {
			if c.Admissions[i].Name == name {
				c.Admissions[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteAdmissionRequest
type deleteAdmissionRequest struct {
	// in: path
	// required: true
	Admission string `uri:"admission" json:"admission"`
}

// successful operation.
// swagger:response deleteAdmissionResponse
type deleteAdmissionResponse struct {
	Data Response
}

func deleteAdmission(ctx *gin.Context) {
	// swagger:route DELETE /config/admissions/{admission} Admission deleteAdmissionRequest
	//
	// Delete admission by name.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteAdmissionResponse

	var req deleteAdmissionRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Admission)

	if !registry.AdmissionRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("admission %s not found", name)))
		return
	}
	registry.AdmissionRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		admissiones := c.Admissions
		c.Admissions = nil
		for _, s := range admissiones {
			if s.Name == name {
				continue
			}
			c.Admissions = append(c.Admissions, s)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
