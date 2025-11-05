package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ldapConstants "goauthentik.io/internal/outpost/ldap/constants"
)

func TestGetNeededObjects_ORFilter(t *testing.T) {
	pi := &ProviderInstance{
		BaseDN:         "dc=example,dc=org",
		UserDN:         "ou=users,dc=example,dc=org",
		GroupDN:        "ou=groups,dc=example,dc=org",
		VirtualGroupDN: "ou=virtual-groups,dc=example,dc=org",
	}

	needUsers, needGroups := pi.GetNeededObjects(2, "dc=example,dc=org", "")
	assert.True(t, needUsers, "Empty filterOC should include users")
	assert.True(t, needGroups, "Empty filterOC should include groups")

	needUsers, needGroups = pi.GetNeededObjects(2, "dc=example,dc=org", ldapConstants.OCPosixAccount)
	assert.True(t, needUsers, "posixAccount filterOC should include users")
	assert.False(t, needGroups, "posixAccount filterOC should not include groups")

	needUsers, needGroups = pi.GetNeededObjects(2, "dc=example,dc=org", ldapConstants.OCPosixGroup)
	assert.False(t, needUsers, "posixGroup filterOC should not include users")
	assert.True(t, needGroups, "posixGroup filterOC should include groups")

	needUsers, needGroups = pi.GetNeededObjects(0, "dc=example,dc=org", "")
	assert.False(t, needUsers, "Scope 0 on base DN should not include users")
	assert.False(t, needGroups, "Scope 0 on base DN should not include groups")

	needUsers, needGroups = pi.GetNeededObjects(1, "ou=users,dc=example,dc=org", "")
	assert.True(t, needUsers, "User DN with scope 1 should include users")
	assert.False(t, needGroups, "User DN with scope 1 should not include groups")

	needUsers, needGroups = pi.GetNeededObjects(1, "ou=groups,dc=example,dc=org", "")
	assert.False(t, needUsers, "Group DN with scope 1 should not include users")
	assert.True(t, needGroups, "Group DN with scope 1 should include groups")
}
