// swagger generate spec -o swagger.yaml

package api

import (
	"embed"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/auth"
)

var (
	//go:embed swagger.yaml
	swaggerDoc embed.FS
)

type Response struct {
	Code int         `json:"code,omitempty"`
	Msg  string      `json:"msg,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

type Options struct {
	AccessLog  bool
	PathPrefix string
	Auther     auth.Authenticator
}

func Register(r *gin.Engine, opts *Options) {
	if opts == nil {
		opts = &Options{}
	}

	r.Use(
		cors.New((cors.Config{
			AllowAllOrigins:     true,
			AllowMethods:        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowHeaders:        []string{"*"},
			AllowPrivateNetwork: true,
		})),
		gin.Recovery(),
	)
	if opts.AccessLog {
		r.Use(mwLogger())
	}

	router := r.Group("")
	if opts.PathPrefix != "" {
		router = router.Group(opts.PathPrefix)
	}

	router.StaticFS("/docs", http.FS(swaggerDoc))

	config := router.Group("/config")
	config.Use(mwBasicAuth(opts.Auther))

	config.GET("", getConfig)
	config.POST("", saveConfig)

	config.POST("/reload", reloadConfig)

	config.GET("/services", getServiceList)
	config.GET("/services/:service", getService)
	config.POST("/services", createService)
	config.PUT("/services/:service", updateService)
	config.DELETE("/services/:service", deleteService)

	config.GET("/chains", getChainList)
	config.GET("/chains/:chain", getChain)
	config.POST("/chains", createChain)
	config.PUT("/chains/:chain", updateChain)
	config.DELETE("/chains/:chain", deleteChain)

	config.GET("/hops", getHopList)
	config.GET("/hops/:hop", getHop)
	config.POST("/hops", createHop)
	config.PUT("/hops/:hop", updateHop)
	config.DELETE("/hops/:hop", deleteHop)

	config.GET("/authers", getAutherList)
	config.GET("/authers/:auther", getAuther)
	config.POST("/authers", createAuther)
	config.PUT("/authers/:auther", updateAuther)
	config.DELETE("/authers/:auther", deleteAuther)

	config.GET("/admissions", getAdmissionList)
	config.GET("/admissions/:admission", getAdmission)
	config.POST("/admissions", createAdmission)
	config.PUT("/admissions/:admission", updateAdmission)
	config.DELETE("/admissions/:admission", deleteAdmission)

	config.GET("/bypasses", getBypassList)
	config.GET("/bypasses/:bypass", getBypass)
	config.POST("/bypasses", createBypass)
	config.PUT("/bypasses/:bypass", updateBypass)
	config.DELETE("/bypasses/:bypass", deleteBypass)

	config.GET("/resolvers", getResolverList)
	config.GET("/resolvers/:resolver", getResolver)
	config.POST("/resolvers", createResolver)
	config.PUT("/resolvers/:resolver", updateResolver)
	config.DELETE("/resolvers/:resolver", deleteResolver)

	config.GET("/hosts", getHostsList)
	config.GET("/hosts/:hosts", getHosts)
	config.POST("/hosts", createHosts)
	config.PUT("/hosts/:hosts", updateHosts)
	config.DELETE("/hosts/:hosts", deleteHosts)

	config.GET("/ingresses", getIngressList)
	config.GET("/ingresses/:ingress", getIngress)
	config.POST("/ingresses", createIngress)
	config.PUT("/ingresses/:ingress", updateIngress)
	config.DELETE("/ingresses/:ingress", deleteIngress)

	config.GET("/routers", getRouterList)
	config.GET("/routers/:router", getRouter)
	config.POST("/routers", createRouter)
	config.PUT("/routers/:router", updateRouter)
	config.DELETE("/routers/:router", deleteRouter)

	config.GET("/observers", getObserverList)
	config.GET("/observers/:observer", getObserver)
	config.POST("/observers", createObserver)
	config.PUT("/observers/:observer", updateObserver)
	config.DELETE("/observers/:observer", deleteObserver)

	config.GET("/recorders", getRecorderList)
	config.GET("/recorders/:recorder", getRecorder)
	config.POST("/recorders", createRecorder)
	config.PUT("/recorders/:recorder", updateRecorder)
	config.DELETE("/recorders/:recorder", deleteRecorder)

	config.GET("/sds", getSDList)
	config.GET("/sds/:sd", getSD)
	config.POST("/sds", createSD)
	config.PUT("/sds/:sd", updateSD)
	config.DELETE("/sds/:sd", deleteSD)

	config.GET("/limiters", getLimiterList)
	config.GET("/limiters/:limiter", getLimiter)
	config.POST("/limiters", createLimiter)
	config.PUT("/limiters/:limiter", updateLimiter)
	config.DELETE("/limiters/:limiter", deleteLimiter)

	config.GET("/climiters", getConnLimiterList)
	config.GET("/climiters/:limiter", getConnLimiter)
	config.POST("/climiters", createConnLimiter)
	config.PUT("/climiters/:limiter", updateConnLimiter)
	config.DELETE("/climiters/:limiter", deleteConnLimiter)

	config.GET("/rlimiters", getRateLimiterList)
	config.GET("/rlimiters/:limiter", getRateLimiter)
	config.POST("/rlimiters", createRateLimiter)
	config.PUT("/rlimiters/:limiter", updateRateLimiter)
	config.DELETE("/rlimiters/:limiter", deleteRateLimiter)
}
