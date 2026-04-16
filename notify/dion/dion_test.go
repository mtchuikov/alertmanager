// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
