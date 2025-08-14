package handlers

import (
	"html/template"
	"log"
	"os"
	"path/filepath"
)

// Template variables for all handlers
var (
	errorTmpl         *template.Template
	setPasswordTmpl   *template.Template
	notFoundTmpl      *template.Template
	loginTmpl         *template.Template
	forgotTmpl        *template.Template
	verifyContactTmpl *template.Template
	templateDir       string
)

// findTemplateDirectory searches for a template directory in common locations
func findTemplateDirectory() string {
	// Define potential template directory paths to search
	searchPaths := []string{
		"tmpl",                               // Alternative current directory
		"apps/default/tmpl",                  // Alternative from project root
		"../tmpl",                            // Alternative parent directory
		"../../tmpl",                         // Alternative two levels up
		"apps/default/service/handlers/tmpl", // Alternative relative to handlers
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			// Check if it's actually a directory
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				// Verify it contains at least one .html file
				if hasHTMLFiles(path) {
					absPath, err := filepath.Abs(path)
					if err == nil {
						log.Printf("Found template directory: %s", absPath)
						return absPath
					}
				}
			}
		}
	}

	log.Printf("Warning: No template directory found in search paths")
	return ""
}

// hasHTMLFiles checks if a directory contains any .html files
func hasHTMLFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".html" {
			return true
		}
	}
	return false
}

func loadTemplate(name string) *template.Template {
	if templateDir == "" {
		templateDir = findTemplateDirectory()
		if templateDir == "" {
			log.Fatalf("No template directory found for template %s", name)
		}
	}

	templatePath := filepath.Join(templateDir, name+".html")
	basePath := filepath.Join(templateDir, "auth_base.html")

	// Check if the specific template file exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		log.Fatalf("Template file not found: %s", templatePath)
	}

	// Load the template, including base template if it exists
	var tmpl *template.Template
	var err error

	if _, err = os.Stat(basePath); err == nil {
		// Load with base template
		tmpl, err = template.ParseFiles(basePath, templatePath)
	} else {
		// Load standalone template
		tmpl, err = template.ParseFiles(templatePath)
	}

	if err != nil {
		log.Fatalf("Failed to load template %s: %v", name, err)
	}

	return tmpl
}

func init() {
	// Load templates from found directory
	errorTmpl = loadTemplate("error")
	notFoundTmpl = loadTemplate("not_found")
	loginTmpl = loadTemplate("login")
	verifyContactTmpl = loadTemplate("contact_verification")
}
