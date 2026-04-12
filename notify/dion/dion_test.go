package dion

import (
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/alertmanager/config"
	commoncfg "github.com/prometheus/common/config"
	"github.com/stretchr/testify/assert/yaml"
	"github.com/stretchr/testify/require"
)

func TestDionUnmarshal(t *testing.T) {
	in := `
route:
  receiver: test
receivers:
- name: test
  dion_configs:
  - chat_id: 8c925d45-d60e-4d9e-8732-04ee5a139752
    bot_email: test@example.com
    bot_password: secret
`
	var c config.Config
	err := yaml.Unmarshal([]byte(in), &c)
	require.NoError(t, err)

	require.Len(t, c.Receivers, 1)
	require.Len(t, c.Receivers[0].DionConfigs, 1)

	require.Equal(t, "https://bots-api.dion.vc", c.Receivers[0].DionConfigs[0].APIURL.String())
	require.Equal(t, commoncfg.Secret("secret"), c.Receivers[0].DionConfigs[0].BotPassword)
	require.Equal(t, uuid.MustParse("8c925d45-d60e-4d9e-8732-04ee5a139752"), c.Receivers[0].DionConfigs[0].ChatID)
	require.Equal(t, "HTML", c.Receivers[0].DionConfigs[0].ParseMode)
}
