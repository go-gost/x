package api

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/registry"
	"github.com/go-gost/x/service"
)

type serviceStatus interface {
	Status() *service.Status
}

// swagger:parameters getConfigRequest
type getConfigRequest struct {
	// output format, one of yaml|json, default is json.
	// in: query
	Format string `form:"format" json:"format"`
}

// successful operation.
// swagger:response getConfigResponse
type getConfigResponse struct {
	Config *config.Config
}

func getConfig(ctx *gin.Context) {
	// swagger:route GET /config Config getConfigRequest
	//
	// Get current config.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getConfigResponse

	var req getConfigRequest
	ctx.ShouldBindQuery(&req)

	config.OnUpdate(func(c *config.Config) error {
		for _, svc := range c.Services {
			if svc == nil {
				continue
			}
			s := registry.ServiceRegistry().Get(svc.Name)
			ss, ok := s.(serviceStatus)
			if ok && ss != nil {
				status := ss.Status()
				svc.Status = &config.ServiceStatus{
					CreateTime: status.CreateTime().Unix(),
					State:      string(status.State()),
				}
				if st := status.Stats(); st != nil {
					svc.Status.Stats = &config.ServiceStats{
						TotalConns:   st.Get(stats.KindTotalConns),
						CurrentConns: st.Get(stats.KindCurrentConns),
						TotalErrs:    st.Get(stats.KindTotalErrs),
						InputBytes:   st.Get(stats.KindInputBytes),
						OutputBytes:  st.Get(stats.KindOutputBytes),
					}
				}
				for _, ev := range status.Events() {
					if !ev.Time.IsZero() {
						svc.Status.Events = append(svc.Status.Events, config.ServiceEvent{
							Time: ev.Time.Unix(),
							Msg:  ev.Message,
						})
					}
				}
			}
		}
		return nil
	})
	var resp getConfigResponse
	resp.Config = config.Global()

	buf := &bytes.Buffer{}
	switch req.Format {
	case "yaml":
	default:
		req.Format = "json"
	}

	resp.Config.Write(buf, req.Format)

	contentType := "application/json"
	if req.Format == "yaml" {
		contentType = "text/x-yaml"
	}

	ctx.Data(http.StatusOK, contentType, buf.Bytes())
}

// swagger:parameters saveConfigRequest
type saveConfigRequest struct {
	// output format, one of yaml|json, default is yaml.
	// in: query
	Format string `form:"format" json:"format"`
	// file path, default is gost.yaml|gost.json in current working directory.
	// in: query
	Path string `form:"path" json:"path"`
}

// successful operation.
// swagger:response saveConfigResponse
type saveConfigResponse struct {
	Data Response
}

func saveConfig(ctx *gin.Context) {
	// swagger:route POST /config Config saveConfigRequest
	//
	// Save current config to file (gost.yaml or gost.json).
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: saveConfigResponse

	var req saveConfigRequest
	ctx.ShouldBindQuery(&req)

	file := "gost.yaml"
	switch req.Format {
	case "json":
		file = "gost.json"
	default:
		req.Format = "yaml"
	}

	if req.Path != "" {
		file = req.Path
	}

	f, err := os.Create(file)
	if err != nil {
		writeError(ctx, &Error{
			statusCode: http.StatusInternalServerError,
			Code:       ErrCodeSaveConfigFailed,
			Msg:        fmt.Sprintf("create file: %s", err.Error()),
		})
		return
	}
	defer f.Close()

	if err := config.Global().Write(f, req.Format); err != nil {
		writeError(ctx, &Error{
			statusCode: http.StatusInternalServerError,
			Code:       ErrCodeSaveConfigFailed,
			Msg:        fmt.Sprintf("save config: %s", err.Error()),
		})
		return
	}

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
