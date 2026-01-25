/**
 * Authentication Service JavaScript v1.2.0
 * Enhanced client-side functionality for authentication forms
 */

(function() {
    'use strict';

    // ==========================================================================
    // Configuration
    // ==========================================================================

    const CONFIG = {
        RESEND_COOLDOWN_SECONDS: 60,
        VERIFICATION_CODE_LENGTH: 6,
        DEBOUNCE_DELAY: 300,
    };

    // ==========================================================================
    // Utility Functions
    // ==========================================================================

    /**
     * Debounce function execution
     */
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * Show inline error message for a field
     */
    function showFieldError(input, message) {
        // Remove any existing error
        clearFieldError(input);

        const errorEl = document.createElement('div');
        errorEl.className = 'field-error';
        errorEl.setAttribute('role', 'alert');
        errorEl.textContent = message;
        errorEl.style.cssText = 'color: var(--auth-error); font-size: 0.85rem; margin-top: 0.25rem;';

        input.setAttribute('aria-invalid', 'true');
        input.setAttribute('aria-describedby', input.id + '-error');
        errorEl.id = input.id + '-error';

        input.parentNode.appendChild(errorEl);
    }

    /**
     * Clear error message for a field
     */
    function clearFieldError(input) {
        const existingError = input.parentNode.querySelector('.field-error');
        if (existingError) {
            existingError.remove();
        }
        input.removeAttribute('aria-invalid');
    }

    /**
     * Add loading state to button
     */
    function setButtonLoading(button, isLoading) {
        if (isLoading) {
            button.classList.add('btn-loading');
            button.disabled = true;
            button.setAttribute('aria-busy', 'true');
        } else {
            button.classList.remove('btn-loading');
            button.disabled = false;
            button.removeAttribute('aria-busy');
        }
    }

    /**
     * Show verification overlay and clear sensitive form data
     * This prevents the verification page from being visible during redirect
     * and protects against back-button exposure on mobile devices
     */
    function showVerificationOverlay() {
        const overlay = document.getElementById('verificationOverlay');
        const codeInput = document.getElementById('verification_code');

        // Show the overlay immediately
        if (overlay) {
            overlay.style.display = 'flex';
        }

        // Clear the verification code from the input for security
        if (codeInput) {
            codeInput.value = '';
        }

        // Replace current history entry to prevent back-button exposure
        // This ensures the user can't press back to see the verification page
        if (window.history && window.history.replaceState) {
            try {
                window.history.replaceState(null, '', window.location.href);
            } catch (e) {
                // Ignore errors in restricted contexts
            }
        }

        // Auto-close tab after 1 minute for security
        // If redirect hasn't happened by then, something went wrong
        setTimeout(function() {
            closeOrClearPage();
        }, 60000);
    }

    /**
     * Attempt to close the tab, or clear the page if closing is not allowed
     * Browsers only allow window.close() for tabs opened via JavaScript
     */
    function closeOrClearPage() {
        // Clear all sensitive form data first
        const form = document.getElementById('verificationForm');
        if (form) {
            form.remove();
        }

        // Try to close the tab
        try {
            window.close();
        } catch (e) {
            // Ignore close errors
        }

        // If we're still here after 100ms, the tab didn't close
        // Replace page content with a safe message
        setTimeout(function() {
            // Check if page is still open (close might have worked)
            if (!window.closed) {
                document.body.innerHTML =
                    '<div style="display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:system-ui,sans-serif;text-align:center;padding:2rem;">' +
                    '<div>' +
                    '<h1 style="font-size:1.5rem;margin-bottom:1rem;">Login Succeeded</h1>' +
                    '<p style="color:#666;margin-bottom:1.5rem;">You can now close this tab.</p>' +
                    '<button onclick="window.close()" style="padding:0.75rem 1.5rem;background:#0066cc;color:white;border:none;border-radius:0.5rem;cursor:pointer;font-size:1rem;">Close Tab</button>' +
                    '</div>' +
                    '</div>';

                // Clear history to prevent back navigation
                if (window.history && window.history.replaceState) {
                    window.history.replaceState(null, '', 'about:blank');
                }
            }
        }, 100);
    }

    // ==========================================================================
    // Validation Functions
    // ==========================================================================

    /**
     * Validate email format
     */
    function validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }

    /**
     * Validate phone number format (international)
     */
    function validatePhone(phone) {
        // Remove spaces and dashes for validation
        const cleaned = phone.replace(/[\s\-\(\)]/g, '');
        // Accepts formats: +1234567890, 1234567890, with optional country code
        const re = /^\+?[1-9]\d{6,14}$/;
        return re.test(cleaned);
    }

    /**
     * Validate contact (email or phone)
     */
    function validateContact(value) {
        const trimmed = value.trim();
        if (!trimmed) {
            return { valid: false, message: 'Please enter your email or phone number' };
        }

        // Check if it looks like a phone number (starts with + or contains mostly digits)
        const looksLikePhone = /^\+/.test(trimmed) || /^\d[\d\s\-]{5,}$/.test(trimmed);

        if (looksLikePhone) {
            if (validatePhone(trimmed)) {
                return { valid: true };
            }
            return { valid: false, message: 'Please enter a valid phone number (e.g., +1234567890)' };
        }

        if (validateEmail(trimmed)) {
            return { valid: true };
        }

        return { valid: false, message: 'Please enter a valid email address' };
    }

    /**
     * Validate verification code (alphanumeric, 6 characters)
     */
    function validateVerificationCode(code) {
        const cleaned = code.replace(/\s/g, '');
        const re = /^[a-zA-Z0-9]{6}$/;
        return re.test(cleaned);
    }

    // ==========================================================================
    // Form Handlers
    // ==========================================================================

    /**
     * Initialize contact login form
     */
    function initContactLoginForm() {
        const form = document.getElementById('contactLoginForm') || document.querySelector('.contact-login-form');
        if (!form) return;

        const contactInput = form.querySelector('input[name="contact"]');
        const submitBtn = form.querySelector('button[type="submit"]');

        if (!contactInput) return;

        // Real-time validation with debounce
        const debouncedValidate = debounce(() => {
            if (contactInput.value.trim()) {
                const result = validateContact(contactInput.value);
                if (!result.valid) {
                    showFieldError(contactInput, result.message);
                } else {
                    clearFieldError(contactInput);
                }
            }
        }, CONFIG.DEBOUNCE_DELAY);

        contactInput.addEventListener('input', () => {
            clearFieldError(contactInput);
            debouncedValidate();
        });

        contactInput.addEventListener('blur', () => {
            if (contactInput.value.trim()) {
                const result = validateContact(contactInput.value);
                if (!result.valid) {
                    showFieldError(contactInput, result.message);
                }
            }
        });

        // Form submission
        form.addEventListener('submit', function(e) {
            const result = validateContact(contactInput.value);
            if (!result.valid) {
                e.preventDefault();
                showFieldError(contactInput, result.message);
                contactInput.focus();
                return false;
            }

            // Show loading state
            if (submitBtn) {
                setButtonLoading(submitBtn, true);
            }
        });
    }

    /**
     * Initialize verification form
     */
    function initVerificationForm() {
        const form = document.getElementById('verificationForm') || document.querySelector('.verification-form');
        if (!form) return;

        const codeInput = document.getElementById('verification_code');
        const nameInput = document.getElementById('profile_name');
        const submitBtn = form.querySelector('button[type="submit"]');

        if (codeInput) {
            // Allow alphanumeric input, convert to uppercase for consistency
            codeInput.addEventListener('input', function(e) {
                // Remove any non-alphanumeric characters and convert to uppercase
                this.value = this.value.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();

                // Clear any previous error when user types
                clearFieldError(this);

                // Auto-submit when 6 characters are entered and name is filled
                if (this.value.length === CONFIG.VERIFICATION_CODE_LENGTH) {
                    if (nameInput && nameInput.value.trim()) {
                        // Visual feedback before auto-submit
                        this.style.borderColor = 'var(--auth-success)';
                        // Auto-submit after short delay for visual feedback
                        setTimeout(() => {
                            if (submitBtn) {
                                setButtonLoading(submitBtn, true);
                            }
                            // Show overlay before form submission
                            showVerificationOverlay();
                            form.submit();
                        }, 300);
                    } else if (nameInput) {
                        nameInput.focus();
                    }
                }
            });

            // Paste handling - allow alphanumeric characters
            codeInput.addEventListener('paste', function(e) {
                e.preventDefault();
                const pastedText = (e.clipboardData || window.clipboardData).getData('text');
                const cleaned = pastedText.replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, CONFIG.VERIFICATION_CODE_LENGTH);
                this.value = cleaned;

                // Trigger input event for auto-submit check
                this.dispatchEvent(new Event('input'));
            });

            // Allow alphanumeric key presses
            codeInput.addEventListener('keypress', function(e) {
                if (!/[a-zA-Z0-9]/.test(e.key) && !e.ctrlKey && !e.metaKey) {
                    e.preventDefault();
                }
            });
        }

        // Form submission validation
        form.addEventListener('submit', function(e) {
            let hasError = false;

            // Validate name
            if (nameInput && !nameInput.value.trim()) {
                e.preventDefault();
                showFieldError(nameInput, 'Please enter your name');
                nameInput.focus();
                hasError = true;
            }

            // Validate code
            if (codeInput && !validateVerificationCode(codeInput.value)) {
                e.preventDefault();
                showFieldError(codeInput, 'Please enter a valid 6-character code');
                if (!hasError) {
                    codeInput.focus();
                }
                hasError = true;
            }

            if (!hasError) {
                if (submitBtn) {
                    setButtonLoading(submitBtn, true);
                }
                // Show overlay to hide sensitive data during redirect
                showVerificationOverlay();
            }
        });
    }

    /**
     * Initialize resend code functionality
     */
    function initResendCode() {
        const resendBtn = document.getElementById('resendBtn');
        const resendTimer = document.getElementById('resendTimer');
        const countdown = document.getElementById('countdown');

        if (!resendBtn) return;

        let cooldownActive = false;
        let remainingSeconds = 0;

        window.resendCode = function() {
            if (cooldownActive) return;

            // Start cooldown
            cooldownActive = true;
            remainingSeconds = CONFIG.RESEND_COOLDOWN_SECONDS;

            resendBtn.disabled = true;
            resendBtn.style.opacity = '0.5';

            if (resendTimer) {
                resendTimer.style.display = 'block';
            }

            const timer = setInterval(() => {
                remainingSeconds--;

                if (countdown) {
                    countdown.textContent = remainingSeconds;
                }

                if (remainingSeconds <= 0) {
                    clearInterval(timer);
                    cooldownActive = false;
                    resendBtn.disabled = false;
                    resendBtn.style.opacity = '1';

                    if (resendTimer) {
                        resendTimer.style.display = 'none';
                    }
                }
            }, 1000);

            // TODO: Implement actual resend API call
            // For now, show a message indicating the feature
            const loginEventId = document.querySelector('input[name="login_event_id"]')?.value;
            if (loginEventId) {
                // In production, this would make an API call to resend the code
                console.log('Resending verification code for login event:', loginEventId);

                // Show success feedback
                const footer = document.querySelector('.verification-footer');
                if (footer) {
                    const successMsg = document.createElement('div');
                    successMsg.className = 'alert alert-success';
                    successMsg.style.marginTop = '1rem';
                    successMsg.innerHTML = '<span>A new verification code has been sent!</span>';
                    footer.insertBefore(successMsg, footer.firstChild);

                    // Remove message after 5 seconds
                    setTimeout(() => {
                        successMsg.remove();
                    }, 5000);
                }
            }
        };
    }

    /**
     * Initialize social login buttons
     */
    function initSocialLoginButtons() {
        const socialForms = document.querySelectorAll('.social-login-form');

        socialForms.forEach(form => {
            form.addEventListener('submit', function() {
                const btn = this.querySelector('button');
                if (btn) {
                    setButtonLoading(btn, true);
                }
            });
        });
    }

    /**
     * Auto-focus first empty required input
     */
    function initAutoFocus() {
        // Skip if user has already focused something
        if (document.activeElement && document.activeElement !== document.body) {
            return;
        }

        // On verification page, focus code input if name is filled
        const nameInput = document.getElementById('profile_name');
        const codeInput = document.getElementById('verification_code');

        if (nameInput && codeInput) {
            if (nameInput.value.trim()) {
                codeInput.focus();
            } else {
                nameInput.focus();
            }
            return;
        }

        // Otherwise focus first empty required input
        const inputs = document.querySelectorAll('input[required]:not([type="hidden"])');
        for (const input of inputs) {
            if (!input.value) {
                input.focus();
                break;
            }
        }
    }

    // ==========================================================================
    // Accessibility Enhancements
    // ==========================================================================

    /**
     * Initialize keyboard navigation enhancements
     */
    function initKeyboardNav() {
        // Allow Enter key to trigger social login buttons
        document.querySelectorAll('.btn-social').forEach(btn => {
            btn.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.click();
                }
            });
        });
    }

    /**
     * Announce dynamic content changes to screen readers
     */
    function announceToScreenReader(message) {
        const announcer = document.createElement('div');
        announcer.setAttribute('role', 'status');
        announcer.setAttribute('aria-live', 'polite');
        announcer.setAttribute('aria-atomic', 'true');
        announcer.className = 'sr-only';
        announcer.style.cssText = 'position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden;';
        announcer.textContent = message;

        document.body.appendChild(announcer);

        setTimeout(() => {
            announcer.remove();
        }, 1000);
    }

    // ==========================================================================
    // Error Page Enhancements
    // ==========================================================================

    /**
     * Initialize error page functionality
     */
    function initErrorPage() {
        const errorDetails = document.querySelector('.error-details');
        if (!errorDetails) return;

        // Track if details were viewed (for analytics)
        errorDetails.addEventListener('toggle', function() {
            if (this.open) {
                console.log('User viewed error details');
            }
        });
    }

    // ==========================================================================
    // Initialization
    // ==========================================================================

    function init() {
        // Initialize form handlers
        initContactLoginForm();
        initVerificationForm();
        initResendCode();
        initSocialLoginButtons();

        // Initialize accessibility features
        initAutoFocus();
        initKeyboardNav();

        // Initialize page-specific features
        initErrorPage();

        // Log initialization (helpful for debugging)
        console.log('Auth.js v1.2.0 initialized');
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
