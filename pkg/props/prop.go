package props

import (
	"github.com/magiconair/properties"
	"os"
)

type Properties struct {
	SecretKey string `properties:"secret_key"`
}

var Props Properties

// Config method to get the configuration properties, and it returns a Properties object
func Config() Properties {

	// for production
	sharedEncConfig := os.ExpandEnv("$PBSWORKS_HOME") + "/config/shared/platform.conf"

	p := properties.MustLoadFiles([]string{
		sharedEncConfig,
	}, properties.UTF8, true)
	p.Decode(&Props)

	return Props
}
