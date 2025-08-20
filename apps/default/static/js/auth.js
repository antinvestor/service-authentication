/* Authentication Service JavaScript */
/* Client-side functionality for authentication forms */

/**
 * Resend verification code functionality
 */
function resendCode() {
    // Placeholder for resend functionality
    alert('Resend functionality would be implemented here');
    return false;
}

/**
 * Auto-format verification code input and enhance UX
 */
document.addEventListener('DOMContentLoaded', function() {
    const verificationInput = document.getElementById('verification_code');
    if (verificationInput) {
        // Remove any non-numeric characters
        verificationInput.addEventListener('input', function(e) {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
        
        // Focus the verification input after page load for better UX
        setTimeout(() => {
            const nameInput = document.getElementById('profile_name');
            if (nameInput && nameInput.value) {
                verificationInput.focus();
            }
        }, 100);
    }
    
    // Auto-focus first empty input field
    const inputs = document.querySelectorAll('input[required]');
    for (let input of inputs) {
        if (!input.value) {
            input.focus();
            break;
        }
    }
});

/**
 * Form validation helpers
 */
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePhone(phone) {
    const re = /^[\+]?[1-9][\d]{0,15}$/;
    return re.test(phone.replace(/\s/g, ''));
}

/**
 * Contact form validation
 */
document.addEventListener('DOMContentLoaded', function() {
    const contactForm = document.querySelector('.contact-login-form');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            const contactInput = this.querySelector('input[name="contact"]');
            if (contactInput) {
                const value = contactInput.value.trim();
                if (!validateEmail(value) && !validatePhone(value)) {
                    e.preventDefault();
                    alert('Please enter a valid email address or phone number');
                    contactInput.focus();
                    return false;
                }
            }
        });
    }
});
