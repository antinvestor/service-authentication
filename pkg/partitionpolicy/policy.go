package partitionpolicy

const (
	PropertyAllowAutoAccess       = "allow_auto_access"
	PropertyAllowAutoAccessSetup  = "allow_auto_access_setup"
	PropertyAccessRequestURI      = "access_request_uri"
	PropertyAccessInstructionsURI = "access_instructions_uri"
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
