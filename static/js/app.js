// SSO Test App JavaScript

// Theme management
class ThemeManager {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'auto';
        this.init();
    }

    init() {
        this.applyTheme();
        this.setupThemeToggle();
        
        // Listen for system theme changes
        if (this.theme === 'auto') {
            window.matchMedia('(prefers-color-scheme: dark)')
                .addEventListener('change', () => this.applyTheme());
        }
    }

    applyTheme() {
        let isDark = false;
        
        if (this.theme === 'dark') {
            isDark = true;
        } else if (this.theme === 'light') {
            isDark = false;
        } else {
            // auto
            isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        }
        
        document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
        this.updateToggleIcon(isDark);
    }

    updateToggleIcon(isDark) {
        const icon = document.getElementById('theme-icon');
        if (icon) {
            icon.textContent = isDark ? '☀️' : '🌙';
        }
    }

    setupThemeToggle() {
        const toggle = document.getElementById('theme-toggle');
        if (toggle) {
            toggle.addEventListener('click', () => this.toggleTheme());
        }
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        this.theme = newTheme;
        localStorage.setItem('theme', newTheme);
        this.applyTheme();
    }
}

// Form validation and enhancement
class FormEnhancer {
    constructor() {
        this.init();
    }

    init() {
        this.setupPasswordToggle();
        this.setupFormValidation();
        this.setupAutoComplete();
    }

    setupPasswordToggle() {
        document.querySelectorAll('input[type="password"]').forEach(input => {
            const wrapper = document.createElement('div');
            wrapper.className = 'position-relative';
            
            input.parentNode.insertBefore(wrapper, input);
            wrapper.appendChild(input);
            
            const toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'btn btn-outline-secondary position-absolute top-50 end-0 translate-middle-y me-2';
            toggle.style.zIndex = '10';
            toggle.innerHTML = '👁️';
            toggle.title = 'Toggle password visibility';
            
            toggle.addEventListener('click', () => {
                const type = input.type === 'password' ? 'text' : 'password';
                input.type = type;
                toggle.innerHTML = type === 'password' ? '👁️' : '🙈';
            });
            
            wrapper.appendChild(toggle);
        });
    }

    setupFormValidation() {
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function(e) {
                if (!form.checkValidity()) {
                    e.preventDefault();
                    e.stopPropagation();
                }
                form.classList.add('was-validated');
            });
        });
    }

    setupAutoComplete() {
        // Setup email autocomplete suggestions
        const emailInputs = document.querySelectorAll('input[type="email"]');
        emailInputs.forEach(input => {
            const domains = ['@visiquate.com', '@gmail.com', '@outlook.com', '@company.com'];
            
            input.addEventListener('input', function(e) {
                const value = e.target.value;
                if (value.includes('@')) {
                    const [username] = value.split('@');
                    // Could add dropdown suggestions here
                }
            });
        });
    }
}

// Transaction data display
class TransactionDisplay {
    static formatJSON(data) {
        if (typeof data === 'string') {
            try {
                data = JSON.parse(data);
            } catch (e) {
                return data;
            }
        }
        
        return JSON.stringify(data, null, 2);
    }

    static createExpandableSection(title, content, isExpanded = false) {
        const wrapper = document.createElement('div');
        wrapper.className = 'mb-3';
        
        const button = document.createElement('button');
        button.className = 'btn btn-outline-primary btn-sm w-100 d-flex justify-content-between align-items-center';
        button.type = 'button';
        button.setAttribute('data-bs-toggle', 'collapse');
        button.setAttribute('data-bs-target', `#content-${Date.now()}`);
        
        button.innerHTML = `
            <span>${title}</span>
            <span class="collapse-icon">${isExpanded ? '−' : '+'}</span>
        `;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = `collapse ${isExpanded ? 'show' : ''}`;
        contentDiv.id = button.getAttribute('data-bs-target').substring(1);
        
        const contentBody = document.createElement('div');
        contentBody.className = 'card-body p-3 mt-2';
        contentBody.innerHTML = `<pre><code>${this.formatJSON(content)}</code></pre>`;
        
        contentDiv.appendChild(contentBody);
        wrapper.appendChild(button);
        wrapper.appendChild(contentDiv);
        
        // Update icon on collapse events
        contentDiv.addEventListener('show.bs.collapse', () => {
            button.querySelector('.collapse-icon').textContent = '−';
        });
        
        contentDiv.addEventListener('hide.bs.collapse', () => {
            button.querySelector('.collapse-icon').textContent = '+';
        });
        
        return wrapper;
    }
}

// Toast notifications
class ToastManager {
    constructor() {
        this.container = this.createContainer();
    }

    createContainer() {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container position-fixed top-0 end-0 p-3';
            container.style.zIndex = '1055';
            document.body.appendChild(container);
        }
        return container;
    }

    show(message, type = 'info', duration = 5000) {
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type === 'error' ? 'danger' : type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');
        
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        `;
        
        this.container.appendChild(toast);
        
        const bsToast = new bootstrap.Toast(toast, { delay: duration });
        bsToast.show();
        
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }

    success(message) {
        this.show(message, 'success');
    }

    error(message) {
        this.show(message, 'error');
    }

    warning(message) {
        this.show(message, 'warning');
    }

    info(message) {
        this.show(message, 'info');
    }
}

// Loading states
class LoadingManager {
    static setLoading(element, isLoading, text = 'Loading...') {
        if (isLoading) {
            element.disabled = true;
            element.dataset.originalText = element.textContent;
            element.innerHTML = `
                <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                ${text}
            `;
        } else {
            element.disabled = false;
            element.textContent = element.dataset.originalText || 'Submit';
        }
    }

    static showModal(title, content, isLoading = true) {
        let modal = document.getElementById('dynamic-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'dynamic-modal';
            modal.className = 'modal fade';
            modal.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title"></h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body"></div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        modal.querySelector('.modal-title').textContent = title;
        modal.querySelector('.modal-body').innerHTML = content;

        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        return {
            modal: bsModal,
            element: modal,
            updateContent: (newContent) => {
                modal.querySelector('.modal-body').innerHTML = newContent;
            },
            updateTitle: (newTitle) => {
                modal.querySelector('.modal-title').textContent = newTitle;
            }
        };
    }
}

// Copy to clipboard functionality
class ClipboardManager {
    static async copy(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            const success = document.execCommand('copy');
            document.body.removeChild(textArea);
            return success;
        }
    }

    static addCopyButtons() {
        document.querySelectorAll('pre code, .transaction-details').forEach(element => {
            const wrapper = document.createElement('div');
            wrapper.className = 'position-relative';
            
            element.parentNode.insertBefore(wrapper, element);
            wrapper.appendChild(element);
            
            const button = document.createElement('button');
            button.className = 'btn btn-sm btn-outline-secondary position-absolute top-0 end-0 m-2';
            button.type = 'button';
            button.innerHTML = '📋';
            button.title = 'Copy to clipboard';
            
            button.addEventListener('click', async () => {
                const success = await this.copy(element.textContent);
                if (success) {
                    button.innerHTML = '✓';
                    button.classList.add('btn-success');
                    button.classList.remove('btn-outline-secondary');
                    
                    setTimeout(() => {
                        button.innerHTML = '📋';
                        button.classList.remove('btn-success');
                        button.classList.add('btn-outline-secondary');
                    }, 2000);
                }
            });
            
            wrapper.appendChild(button);
        });
    }
}

// Auto-refresh functionality for admin dashboard
class AutoRefresh {
    constructor(interval = 30000) {
        this.interval = interval;
        this.timer = null;
        this.isActive = false;
    }

    start(callback) {
        if (this.isActive) return;
        
        this.isActive = true;
        this.timer = setInterval(callback, this.interval);
    }

    stop() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
        this.isActive = false;
    }

    restart(callback) {
        this.stop();
        this.start(callback);
    }
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize managers
    window.themeManager = new ThemeManager();
    window.formEnhancer = new FormEnhancer();
    window.toastManager = new ToastManager();
    window.autoRefresh = new AutoRefresh();
    
    // Add copy buttons to code blocks
    ClipboardManager.addCopyButtons();
    
    // Setup auto-refresh for admin pages
    if (document.body.classList.contains('admin-page')) {
        window.autoRefresh.start(() => {
            // Refresh page data
            location.reload();
        });
    }
    
    // Setup form submission handlers
    document.querySelectorAll('form[data-async]').forEach(form => {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const submitBtn = form.querySelector('button[type="submit"]');
            LoadingManager.setLoading(submitBtn, true);
            
            try {
                const formData = new FormData(form);
                const response = await fetch(form.action, {
                    method: form.method,
                    body: formData
                });
                
                if (response.ok) {
                    window.toastManager.success('Operation completed successfully');
                    if (form.dataset.redirect) {
                        window.location.href = form.dataset.redirect;
                    }
                } else {
                    window.toastManager.error('Operation failed');
                }
            } catch (error) {
                window.toastManager.error('Network error: ' + error.message);
            } finally {
                LoadingManager.setLoading(submitBtn, false);
            }
        });
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Alt + T for theme toggle
        if (e.altKey && e.key === 't') {
            e.preventDefault();
            window.themeManager.toggleTheme();
        }
        
        // Alt + A for admin (if admin)
        if (e.altKey && e.key === 'a') {
            const adminLink = document.querySelector('a[href*="admin"]');
            if (adminLink) {
                e.preventDefault();
                adminLink.click();
            }
        }
    });
    
    // Version info in footer
    if (window.GIT_COMMIT) {
        const footer = document.createElement('div');
        footer.className = 'footer text-center text-muted mt-5';
        footer.innerHTML = `
            <div class="container">
                <small class="version-info">
                    Version: ${window.GIT_COMMIT.substring(0, 7)} | 
                    Built: ${window.BUILD_DATE || 'Unknown'}
                </small>
            </div>
        `;
        document.body.appendChild(footer);
    }
});

// Utility functions
window.utils = {
    formatDate: (date) => {
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            timeZoneName: 'short'
        }).format(new Date(date));
    },
    
    formatFileSize: (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    throttle: (func, limit) => {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        }
    }
};