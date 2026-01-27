/**
 * Authentication Service JavaScript v2.0.0
 * Enhanced client-side functionality for authentication forms
 * Features: Accessibility (WCAG 2.1 AA), Progressive Enhancement, Security
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
        SR_ANNOUNCEMENT_DELAY: 100, // Delay before screen reader announcements
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
     * @param {HTMLInputElement} input - The input element
     * @param {string} message - The error message to display
     * @param {boolean} announce - Whether to announce to screen readers (default true)
     */
    function showFieldError(input, message, announce = true) {
        // Remove any existing error
        clearFieldError(input);

        const errorEl = document.createElement('div');
        errorEl.className = 'field-error';
        errorEl.setAttribute('role', 'alert');
        errorEl.textContent = message;
        errorEl.style.cssText = 'color: var(--auth-error); font-size: 0.85rem; margin-top: 0.25rem;';
        errorEl.id = input.id + '-error';

        input.setAttribute('aria-invalid', 'true');
        input.classList.add('is-invalid');
        input.classList.remove('is-valid');

        // Preserve existing aria-describedby and add error
        const existingDescribedBy = input.getAttribute('aria-describedby') || '';
        const describedByIds = existingDescribedBy.split(' ').filter(id => id && id !== errorEl.id);
        describedByIds.push(errorEl.id);
        input.setAttribute('aria-describedby', describedByIds.join(' '));

        input.parentNode.appendChild(errorEl);

        // Announce to screen readers for immediate feedback
        if (announce) {
            const label = input.closest('.form-group')?.querySelector('label')?.textContent?.replace('*', '').trim() || 'Field';
            announceToScreenReader(label + ': ' + message, true);
        }
    }

    /**
     * Show success state for a field
     * @param {HTMLInputElement} input - The input element
     */
    function showFieldSuccess(input) {
        clearFieldError(input);
        input.classList.add('is-valid');
        input.classList.remove('is-invalid');
    }

    /**
     * Clear error message for a field
     * @param {HTMLInputElement} input - The input element
     */
    function clearFieldError(input) {
        const existingError = input.parentNode.querySelector('.field-error');
        if (existingError) {
            // Remove error id from aria-describedby
            const existingDescribedBy = input.getAttribute('aria-describedby') || '';
            const describedByIds = existingDescribedBy.split(' ').filter(id => id && id !== existingError.id);
            if (describedByIds.length > 0) {
                input.setAttribute('aria-describedby', describedByIds.join(' '));
            } else {
                input.removeAttribute('aria-describedby');
            }
            existingError.remove();
        }
        input.removeAttribute('aria-invalid');
        input.classList.remove('is-invalid');
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
     * Validate verification code (numeric, 6 digits)
     */
    function validateVerificationCode(code) {
        const cleaned = code.replace(/\s/g, '');
        const re = /^[0-9]{6}$/;
        return re.test(cleaned);
    }

    // ==========================================================================
    // Form Handlers
    // ==========================================================================

    /**
     * Initialize contact login form with enhanced validation feedback
     */
    function initContactLoginForm() {
        const form = document.getElementById('contactLoginForm') || document.querySelector('.contact-login-form');
        if (!form) return;

        const contactInput = form.querySelector('input[name="contact"]');
        const submitBtn = form.querySelector('button[type="submit"]');

        if (!contactInput) return;

        // Restore aria-describedby if help text exists
        const helpText = contactInput.parentNode.querySelector('.form-help');
        if (helpText && helpText.id) {
            contactInput.setAttribute('aria-describedby', helpText.id);
        }

        // Real-time validation with debounce - shows success state too
        const debouncedValidate = debounce(() => {
            if (contactInput.value.trim()) {
                const result = validateContact(contactInput.value);
                if (!result.valid) {
                    showFieldError(contactInput, result.message, false); // Don't announce during typing
                } else {
                    showFieldSuccess(contactInput);
                }
            }
        }, CONFIG.DEBOUNCE_DELAY);

        contactInput.addEventListener('input', () => {
            clearFieldError(contactInput);
            contactInput.classList.remove('is-valid');
            debouncedValidate();
        });

        contactInput.addEventListener('blur', () => {
            if (contactInput.value.trim()) {
                const result = validateContact(contactInput.value);
                if (!result.valid) {
                    showFieldError(contactInput, result.message);
                } else {
                    showFieldSuccess(contactInput);
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

            // Show loading state and announce
            if (submitBtn) {
                setButtonLoading(submitBtn, true);
                announceToScreenReader('Sending verification code. Please wait.');
            }
        });
    }

    /**
     * Update the page heading and subtitle during step transitions
     */
    function updateStepHeading(title, subtitle) {
        var heading = document.querySelector('.auth-header h1');
        var subtitleEl = document.getElementById('pageSubtitle');
        if (heading) {
            heading.textContent = title;
        }
        if (subtitleEl) {
            subtitleEl.textContent = subtitle;
        }
    }

    /**
     * Initialize verification form with two-step name/code flow
     */
    function initVerificationForm() {
        const form = document.getElementById('verificationForm') || document.querySelector('.verification-form');
        if (!form) return;

        const codeInput = document.getElementById('verification_code');
        const nameHidden = document.getElementById('profile_name_hidden');
        const submitBtn = document.getElementById('verifyBtn');

        // Step transition elements
        const stepName = document.getElementById('stepName');
        const stepCode = document.getElementById('stepCode');
        const nameNextBtn = document.getElementById('nameNextBtn');
        const nameInput = document.getElementById('profile_name_input');
        const verificationHelp = document.getElementById('verificationHelp');

        // Handle name step -> code step transition
        if (nameNextBtn && stepName && stepCode) {
            nameNextBtn.addEventListener('click', function() {
                if (!nameInput || !nameInput.value.trim()) {
                    if (nameInput) {
                        showFieldError(nameInput, 'Please enter your name');
                        nameInput.focus();
                    }
                    return;
                }
                // Copy name to hidden field
                if (nameHidden) {
                    nameHidden.value = nameInput.value.trim();
                }
                // Transition steps
                stepName.style.display = 'none';
                stepCode.style.display = '';
                if (verificationHelp) {
                    verificationHelp.style.display = '';
                }
                // Update heading text
                updateStepHeading('Enter Verification Code', 'Check your email or phone for the code we sent');
                // Announce step change to screen readers
                announceToScreenReader('Enter the verification code sent to your email or phone.');
                // Focus code input
                if (codeInput) {
                    codeInput.focus();
                }
            });

            // Allow Enter key to advance from name step
            if (nameInput) {
                nameInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        nameNextBtn.click();
                    }
                });
            }
        }

        if (codeInput) {
            // Allow numeric input only
            codeInput.addEventListener('input', function(e) {
                // Remove any non-numeric characters
                this.value = this.value.replace(/[^0-9]/g, '');

                // Clear any previous error when user types
                clearFieldError(this);

                // Auto-submit when 6 characters are entered (name is already in hidden field)
                if (this.value.length === CONFIG.VERIFICATION_CODE_LENGTH) {
                    if (nameHidden && nameHidden.value.trim()) {
                        // Visual feedback before auto-submit
                        this.classList.add('is-valid');
                        this.style.borderColor = 'var(--auth-success)';

                        // Announce auto-submit to screen readers
                        announceToScreenReader('Verification code complete. Verifying now.');

                        // Auto-submit after short delay for visual feedback
                        setTimeout(() => {
                            if (submitBtn) {
                                setButtonLoading(submitBtn, true);
                            }
                            // Show overlay before form submission
                            showVerificationOverlay();
                            form.submit();
                        }, 300);
                    }
                }
            });

            // Paste handling - allow numeric characters only
            codeInput.addEventListener('paste', function(e) {
                e.preventDefault();
                const pastedText = (e.clipboardData || window.clipboardData).getData('text');
                const cleaned = pastedText.replace(/[^0-9]/g, '').slice(0, CONFIG.VERIFICATION_CODE_LENGTH);
                this.value = cleaned;

                // Trigger input event for auto-submit check
                this.dispatchEvent(new Event('input'));
            });

            // Allow numeric key presses only
            codeInput.addEventListener('keypress', function(e) {
                if (!/[0-9]/.test(e.key) && !e.ctrlKey && !e.metaKey) {
                    e.preventDefault();
                }
            });
        }

        // Form submission validation
        form.addEventListener('submit', function(e) {
            let hasError = false;

            // Validate hidden name field
            if (nameHidden && !nameHidden.value.trim()) {
                e.preventDefault();
                // If name step is visible, show error there
                if (nameInput && stepName && stepName.style.display !== 'none') {
                    showFieldError(nameInput, 'Please enter your name');
                    nameInput.focus();
                }
                hasError = true;
            }

            // Validate code
            if (codeInput && !validateVerificationCode(codeInput.value)) {
                e.preventDefault();
                showFieldError(codeInput, 'Please enter a valid 6-digit code');
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
     * Initialize resend code functionality with full accessibility support
     */
    function initResendCode() {
        const resendBtn = document.getElementById('resendBtn');
        const resendTimer = document.getElementById('resendTimer');
        const countdown = document.getElementById('countdown');
        const resendStatus = document.getElementById('resend-status');

        if (!resendBtn) return;

        let cooldownActive = false;
        let remainingSeconds = 0;

        /**
         * Update the screen reader status for resend cooldown
         */
        function updateResendStatus(message) {
            if (resendStatus) {
                resendStatus.textContent = message;
            }
        }

        window.resendCode = function() {
            if (cooldownActive) return;

            // Start cooldown
            cooldownActive = true;
            remainingSeconds = CONFIG.RESEND_COOLDOWN_SECONDS;

            resendBtn.disabled = true;
            resendBtn.setAttribute('aria-disabled', 'true');

            if (resendTimer) {
                resendTimer.style.display = 'inline';
            }

            // Announce to screen readers
            announceToScreenReader('Verification code sent. Please wait ' + remainingSeconds + ' seconds before requesting another code.');
            updateResendStatus('Please wait ' + remainingSeconds + ' seconds');

            const timer = setInterval(() => {
                remainingSeconds--;

                if (countdown) {
                    countdown.textContent = remainingSeconds;
                }

                // Announce every 15 seconds to screen readers
                if (remainingSeconds > 0 && remainingSeconds % 15 === 0) {
                    updateResendStatus(remainingSeconds + ' seconds remaining');
                }

                if (remainingSeconds <= 0) {
                    clearInterval(timer);
                    cooldownActive = false;
                    resendBtn.disabled = false;
                    resendBtn.removeAttribute('aria-disabled');

                    if (resendTimer) {
                        resendTimer.style.display = 'none';
                    }

                    updateResendStatus('You can now request a new code');
                    announceToScreenReader('You can now request a new verification code.');
                }
            }, 1000);

            // TODO: Implement actual resend API call
            // For now, show a message indicating the feature
            const loginEventId = document.querySelector('input[name="login_event_id"]')?.value;
            if (loginEventId) {
                // In production, this would make an API call to resend the code
                console.log('Resending verification code for login event:', loginEventId);

                // Show success feedback in the verification-help section
                const helpSection = document.querySelector('.verification-help');
                if (helpSection) {
                    // Check if success message already exists
                    const existingMsg = helpSection.querySelector('.resend-success');
                    if (existingMsg) {
                        existingMsg.remove();
                    }

                    const successMsg = document.createElement('div');
                    successMsg.className = 'alert alert-success resend-success';
                    successMsg.setAttribute('role', 'status');
                    successMsg.style.cssText = 'margin-top: 1rem; padding: 0.75rem;';
                    successMsg.innerHTML = `
                        <svg class="alert-icon" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" style="width:18px;height:18px;flex-shrink:0;">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                        </svg>
                        <span>A new verification code has been sent!</span>
                    `;
                    helpSection.parentNode.insertBefore(successMsg, helpSection);

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

        // Two-step verification page: focus based on which step is visible
        const stepName = document.getElementById('stepName');
        const stepCode = document.getElementById('stepCode');
        const nameInput = document.getElementById('profile_name_input');
        const codeInput = document.getElementById('verification_code');

        if (stepName && stepCode) {
            if (stepName.style.display !== 'none' && nameInput) {
                nameInput.focus();
            } else if (stepCode.style.display !== 'none' && codeInput) {
                codeInput.focus();
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
     * Uses the dedicated live region from the template for better reliability
     * @param {string} message - The message to announce
     * @param {boolean} assertive - Use assertive (immediate) instead of polite (queued)
     */
    function announceToScreenReader(message, assertive = false) {
        // Try to use the dedicated live region first
        const liveRegion = document.getElementById('liveRegion');
        if (liveRegion) {
            // Set the appropriate aria-live value
            liveRegion.setAttribute('aria-live', assertive ? 'assertive' : 'polite');

            // Clear and set content with a small delay to ensure announcement
            liveRegion.textContent = '';
            setTimeout(() => {
                liveRegion.textContent = message;
            }, CONFIG.SR_ANNOUNCEMENT_DELAY);

            // Clear after announcement is read
            setTimeout(() => {
                liveRegion.textContent = '';
            }, 3000);
            return;
        }

        // Fallback: Create temporary announcer element
        const announcer = document.createElement('div');
        announcer.setAttribute('role', 'status');
        announcer.setAttribute('aria-live', assertive ? 'assertive' : 'polite');
        announcer.setAttribute('aria-atomic', 'true');
        announcer.className = 'sr-only';
        announcer.style.cssText = 'position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden;';
        announcer.textContent = message;

        document.body.appendChild(announcer);

        setTimeout(() => {
            announcer.remove();
        }, 3000);
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

        // Mark body as JS-enabled for progressive enhancement
        document.body.classList.add('js-enabled');

        // Log initialization (helpful for debugging)
        console.log('Auth.js v2.0.0 initialized');
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
