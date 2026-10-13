// AEGENTRA Vulnerable Test Application JavaScript

// Document ready function
document.addEventListener('DOMContentLoaded', function() {
    // Add some basic interactivity
    console.log('AEGENTRA Vulnerable Test Application loaded');
    
    // Highlight vulnerability demos
    const vulnerabilityDemos = document.querySelectorAll('.alert-warning');
    vulnerabilityDemos.forEach(function(element) {
        element.style.borderLeft = '4px solid #ffc107';
    });
    
    // Add click handlers for test case links
    const testCaseLinks = document.querySelectorAll('a[href*="OR"], a[href*="UNION"], a[href*="script"]');
    testCaseLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            const confirmed = confirm('This is a security test. Are you sure you want to proceed?');
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });
    
    // Auto-hide flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            alert.style.opacity = '0';
            setTimeout(function() {
                alert.remove();
            }, 300);
        }, 5000);
    });
});

// Function to demonstrate XSS (intentionally vulnerable)
function demonstrateXSS(payload) {
    // This function is intentionally vulnerable to XSS
    document.getElementById('demo-output').innerHTML = payload;
}

// Function to test SQL injection payloads
function testSQLInjection(payload) {
    console.log('Testing SQL injection payload:', payload);
    // In a real application, this would be sanitized
    return payload;
}

// Function to demonstrate path traversal
function testPathTraversal(path) {
    console.log('Testing path traversal:', path);
    // In a real application, this would be validated
    return path;
}