package servers

import (
	"authentication/config"
)

func Init() {
	config := config.GetConfig()
	r := NewRouter()
	r.Run(":" + config.GetString("app.port"))
}
