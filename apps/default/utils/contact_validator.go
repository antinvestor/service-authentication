package utils

import (
	"regexp"
	"strings"
)

// ContactType represents the type of contact information
type ContactType int

const (
	ContactTypeUnknown ContactType = iota
	ContactTypeEmail
	ContactTypePhone
)

// String returns the string representation of ContactType
func (ct ContactType) String() string {
	switch ct {
	case ContactTypeEmail:
		return "email"
	case ContactTypePhone:
		return "phone"
	default:
		return "unknown"
	}
}

// IsEmail checks if the given string is a valid email format
func IsEmail(contact string) bool {
	// Simple email regex pattern
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(strings.TrimSpace(contact))
}

// IsPhoneNumber checks if the given string is a valid phone number format
func IsPhoneNumber(contact string) bool {
	// Remove common phone number separators and spaces
	cleaned := regexp.MustCompile(`[\s\-\(\)\+\.]`).ReplaceAllString(contact, "")

	// Check if it contains only digits after cleaning
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(cleaned) {
		return false
	}

	// Phone numbers should be between 7 and 15 digits (international standard)
	length := len(cleaned)
	return length >= 7 && length <= 15
}

// GetContactType determines whether a contact string is an email or phone number
func GetContactType(contact string) ContactType {
	contact = strings.TrimSpace(contact)

	if contact == "" {
		return ContactTypeUnknown
	}

	if IsEmail(contact) {
		return ContactTypeEmail
	}

	if IsPhoneNumber(contact) {
		return ContactTypePhone
	}

	return ContactTypeUnknown
}

// ValidateContact validates a contact string and returns its type and validity
func ValidateContact(contact string) (ContactType, bool) {
	contactType := GetContactType(contact)
	return contactType, contactType != ContactTypeUnknown
}
