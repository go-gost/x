package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/quota"
	"github.com/go-gost/x/limiter/quota"
	"github.com/go-gost/x/registry"
)

func fillQuotaStatus(q *config.QuotaConfig) {
	lim := registry.QuotaLimiterRegistry().Get(q.Name)
	if lim == nil {
		return
	}
	s := lim.Snapshot()
	q.Status = &config.QuotaStatus{
		Used:      s.Used,
		Limit:     s.Limit,
		StartsAt:  s.StartsAtUnix,
		ExpiresAt: s.ExpiresAtUnix,
		Active:    s.Active,
		Expired:   s.Expired,
		Blocked:   s.Blocked,
		Direction: s.Direction,
	}
}

// swagger:parameters getQuotaListRequest
type getQuotaListRequest struct {
}

// successful operation.
// swagger:response getQuotaListResponse
type getQuotaListResponse struct {
	// in: body
	Data quotaList
}

type quotaList struct {
	Count int                   `json:"count"`
	List  []*config.QuotaConfig `json:"list"`
}

func getQuotaList(ctx *gin.Context) {
	// swagger:route GET /config/quotas Quota getQuotaListRequest
	//
	// Get quota list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getQuotaListResponse

	var req getQuotaListRequest
	ctx.ShouldBindQuery(&req)

	list := config.Global().Quotas
	for _, q := range list {
		if q == nil {
			continue
		}
		fillQuotaStatus(q)
	}

	ctx.JSON(http.StatusOK, Response{
		Data: quotaList{
			Count: len(list),
			List:  list,
		},
	})
}

// swagger:parameters getQuotaRequest
type getQuotaRequest struct {
	// in: path
	// required: true
	Quota string `uri:"quota" json:"quota"`
}

// successful operation.
// swagger:response getQuotaResponse
type getQuotaResponse struct {
	// in: body
	Data *config.QuotaConfig
}

func getQuota(ctx *gin.Context) {
	// swagger:route GET /config/quotas/{quota} Quota getQuotaRequest
	//
	// Get quota.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: getQuotaResponse

	var req getQuotaRequest
	ctx.ShouldBindUri(&req)

	var resp getQuotaResponse

	for _, q := range config.Global().Quotas {
		if q == nil {
			continue
		}
		if q.Name == req.Quota {
			fillQuotaStatus(q)
			resp.Data = q
		}
	}

	ctx.JSON(http.StatusOK, Response{
		Data: resp.Data,
	})
}

// swagger:parameters createQuotaRequest
type createQuotaRequest struct {
	// in: body
	Data config.QuotaConfig `json:"data"`
}

// successful operation.
// swagger:response createQuotaResponse
type createQuotaResponse struct {
	Data Response
}

func createQuota(ctx *gin.Context) {
	// swagger:route POST /config/quotas Quota createQuotaRequest
	//
	// Create a new quota, the name of the quota must be unique in quota list.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: createQuotaResponse

	var req createQuotaRequest
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Data.Name)
	if name == "" {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeInvalid, "quota name is required"))
		return
	}
	req.Data.Name = name
	req.Data.Status = nil

	if registry.QuotaLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("quota %s already exists", name)))
		return
	}

	v := parser.ParseQuotaLimiter(&req.Data)

	if err := registry.QuotaLimiterRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("quota %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		c.Quotas = append(c.Quotas, &req.Data)
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters updateQuotaRequest
type updateQuotaRequest struct {
	// in: path
	// required: true
	Quota string `uri:"quota" json:"quota"`
	// in: body
	Data config.QuotaConfig `json:"data"`
}

// successful operation.
// swagger:response updateQuotaResponse
type updateQuotaResponse struct {
	Data Response
}

func updateQuota(ctx *gin.Context) {
	// swagger:route PUT /config/quotas/{quota} Quota updateQuotaRequest
	//
	// Update quota by name, the quota must already exist. The cumulative counter
	// is preserved across the update as long as the window is unchanged.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: updateQuotaResponse

	var req updateQuotaRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Quota)

	if !registry.QuotaLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("quota %s not found", name)))
		return
	}

	req.Data.Name = name
	req.Data.Status = nil

	v := parser.ParseQuotaLimiter(&req.Data)

	registry.QuotaLimiterRegistry().Unregister(name)

	if err := registry.QuotaLimiterRegistry().Register(name, v); err != nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeDup, fmt.Sprintf("quota %s already exists", name)))
		return
	}

	config.OnUpdate(func(c *config.Config) error {
		for i := range c.Quotas {
			if c.Quotas[i].Name == name {
				c.Quotas[i] = &req.Data
				break
			}
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters deleteQuotaRequest
type deleteQuotaRequest struct {
	// in: path
	// required: true
	Quota string `uri:"quota" json:"quota"`
}

// successful operation.
// swagger:response deleteQuotaResponse
type deleteQuotaResponse struct {
	Data Response
}

func deleteQuota(ctx *gin.Context) {
	// swagger:route DELETE /config/quotas/{quota} Quota deleteQuotaRequest
	//
	// Delete quota by name. Services referencing it stop being limited (fail-open).
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: deleteQuotaResponse

	var req deleteQuotaRequest
	ctx.ShouldBindUri(&req)

	name := strings.TrimSpace(req.Quota)

	if !registry.QuotaLimiterRegistry().IsRegistered(name) {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("quota %s not found", name)))
		return
	}
	registry.QuotaLimiterRegistry().Unregister(name)

	config.OnUpdate(func(c *config.Config) error {
		quotas := c.Quotas
		c.Quotas = nil
		for _, q := range quotas {
			if q.Name == name {
				continue
			}
			c.Quotas = append(c.Quotas, q)
		}
		return nil
	})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}

// swagger:parameters resetQuotaRequest
type resetQuotaRequest struct {
	// in: path
	// required: true
	Quota string `uri:"quota" json:"quota"`
	// in: body
	Data resetQuotaData `json:"data"`
}

type resetQuotaData struct {
	Used *uint64 `json:"used,omitempty"`
}

// successful operation.
// swagger:response resetQuotaResponse
type resetQuotaResponse struct {
	Data Response
}

func resetQuota(ctx *gin.Context) {
	// swagger:route POST /config/quotas/{quota}/reset Quota resetQuotaRequest
	//
	// Overwrite the cumulative counter of a quota (defaults to 0). The new value
	// is applied immediately and persisted; if the quota was blocking, services
	// resume once the value is below the limit.
	//
	//     Security:
	//       basicAuth: []
	//
	//     Responses:
	//       200: resetQuotaResponse

	var req resetQuotaRequest
	ctx.ShouldBindUri(&req)
	ctx.ShouldBindJSON(&req.Data)

	name := strings.TrimSpace(req.Quota)

	lim := registry.QuotaLimiterRegistry().Get(name)
	if lim == nil {
		writeError(ctx, NewError(http.StatusBadRequest, ErrCodeNotFound, fmt.Sprintf("quota %s not found", name)))
		return
	}

	used := uint64(0)
	if req.Data.Used != nil {
		used = *req.Data.Used
	}
	lim.Update(quota.Update{Used: &used})

	ctx.JSON(http.StatusOK, Response{
		Msg: "OK",
	})
}
