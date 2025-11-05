package search

import (
	"net"
	"testing"

	"beryju.io/ldap"
	"github.com/stretchr/testify/assert"
)

func TestNewRequest_ORFilter(t *testing.T) {
	conn := &net.TCPConn{}

	searchReq := ldap.SearchRequest{
		BaseDN: "dc=example,dc=org",
		Filter: "(|(objectClass=posixGroup)(objectClass=posixAccount))",
		Scope:  ldap.ScopeWholeSubtree,
	}

	req, span := NewRequest("cn=test,dc=example,dc=org", searchReq, conn)
	defer span.Finish()

	assert.Equal(t, "", req.FilterObjectClass, "OR filter with objectClass should result in empty FilterObjectClass")

	searchReq2 := ldap.SearchRequest{
		BaseDN: "dc=example,dc=org",
		Filter: "(objectClass=posixGroup)",
		Scope:  ldap.ScopeWholeSubtree,
	}

	req2, span2 := NewRequest("cn=test,dc=example,dc=org", searchReq2, conn)
	defer span2.Finish()

	assert.NotNil(t, req2.FilterObjectClass)

	searchReq3 := ldap.SearchRequest{
		BaseDN: "dc=example,dc=org",
		Filter: "(|(cn=test)(uid=test))",
		Scope:  ldap.ScopeWholeSubtree,
	}

	req3, span3 := NewRequest("cn=test,dc=example,dc=org", searchReq3, conn)
	defer span3.Finish()

	assert.NotNil(t, req3)
}
