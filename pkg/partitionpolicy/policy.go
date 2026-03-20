package partitionpolicy

import "strings"

const (
	PropertyAllowAutoAccess       = "allow_auto_access"
	PropertyAllowAutoAccessSetup  = "allow_auto_access_setup"
	PropertyAccessRequestURI      = "access_request_uri"
	PropertyAccessInstructionsURI = "access_instructions_uri"
	PropertySupportContacts       = "support_contacts"
)

func AllowAutoAccess(properties map[string]any, defaultValue bool) bool {
	if len(properties) == 0 {
		return defaultValue
	}

	if allow, ok := boolProperty(properties, PropertyAllowAutoAccess); ok {
		return allow
	}
	if allow, ok := boolProperty(properties, PropertyAllowAutoAccessSetup); ok {
		return allow
	}

	return defaultValue
}

func AccessRequestURI(properties map[string]any) string {
	if len(properties) == 0 {
		return ""
	}

	if uri, ok := stringProperty(properties, PropertyAccessRequestURI); ok {
		return uri
	}
	if uri, ok := stringProperty(properties, PropertyAccessInstructionsURI); ok {
		return uri
	}

	return ""
}

func SupportContacts(properties map[string]any) map[string]string {
	contacts := make(map[string]string)
	if len(properties) == 0 {
		return contacts
	}

	nested, ok := properties[PropertySupportContacts].(map[string]any)
	if ok {
		for key, value := range nested {
			stringValue, stringOK := value.(string)
			if !stringOK {
				continue
			}

			stringValue = strings.TrimSpace(stringValue)
			if stringValue == "" {
				continue
			}

			contacts[key] = stringValue
		}
	}

	for _, fallback := range []struct {
		source string
		target string
	}{
		{source: "email", target: "email"},
		{source: "support_email", target: "email"},
		{source: "msisdn", target: "msisdn"},
		{source: "phone", target: "msisdn"},
		{source: "support_phone", target: "msisdn"},
	} {
		if _, exists := contacts[fallback.target]; exists {
			continue
		}

		value, ok := stringProperty(properties, fallback.source)
		if ok {
			contacts[fallback.target] = strings.TrimSpace(value)
		}
	}

	return contacts
}

func boolProperty(properties map[string]any, key string) (bool, bool) {
	value, ok := properties[key]
	if !ok {
		return false, false
	}

	allow, ok := value.(bool)
	return allow, ok
}

func stringProperty(properties map[string]any, key string) (string, bool) {
	value, ok := properties[key]
	if !ok {
		return "", false
	}

	uri, ok := value.(string)
	return uri, ok && uri != ""
}
