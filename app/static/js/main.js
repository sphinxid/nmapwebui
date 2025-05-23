// Main JavaScript file for NmapWebUI

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Auto-close alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Auto-refresh for running scans
    const scanStatusElements = document.querySelectorAll('[data-scan-status]');
    if (scanStatusElements.length > 0) {
        setInterval(function() {
            scanStatusElements.forEach(function(element) {
                const runId = element.dataset.scanId;
                if (element.dataset.scanStatus === 'running' || element.dataset.scanStatus === 'queued') {
                    fetch(`/tasks/api/status/${runId}`)
                        .then(response => response.json())
                        .then(data => {
                            // Update status text
                            const statusBadge = element.querySelector('.status-badge');
                            if (statusBadge) {
                                if (data.status === 'queued') {
                                    statusBadge.className = 'badge bg-secondary status-badge';
                                    statusBadge.textContent = 'Queued';
                                } else if (data.status === 'running') {
                                    statusBadge.className = 'badge bg-primary status-badge';
                                    statusBadge.textContent = 'Running';
                                } else if (data.status === 'completed') {
                                    statusBadge.className = 'badge bg-success status-badge';
                                    statusBadge.textContent = 'Completed';
                                    element.dataset.scanStatus = 'completed';
                                } else if (data.status === 'failed') {
                                    statusBadge.className = 'badge bg-danger status-badge';
                                    statusBadge.textContent = 'Failed';
                                    element.dataset.scanStatus = 'failed';
                                }
                            }
                            
                            // Update progress bar if exists
                            const progressBar = element.querySelector('.progress-bar');
                            if (progressBar && data.status === 'running') {
                                progressBar.style.width = `${data.progress}%`;
                                progressBar.setAttribute('aria-valuenow', data.progress);
                            }
                            
                            // If scan is complete, refresh the page after a short delay
                            if (data.status === 'completed' || data.status === 'failed') {
                                setTimeout(function() {
                                    window.location.reload();
                                }, 2000);
                            }
                        })
                        .catch(error => console.error('Error fetching scan status:', error));
                }
            });
        }, 5000); // Check every 5 seconds
    }
    
    // Target group selection in scan task form
    const targetGroupSelect = document.getElementById('target_groups');
    if (targetGroupSelect) {
        // Add a helper text about multi-select
        const helpText = document.createElement('small');
        helpText.className = 'form-text text-muted';
        helpText.textContent = 'Hold Ctrl (Windows) or Command (Mac) to select multiple target groups.';
        targetGroupSelect.parentNode.appendChild(helpText);
    }
    
    // Toggle custom args field based on scan profile selection
    const scanProfileSelect = document.getElementById('scanProfileSelect');
    const customArgsDiv = document.getElementById('customArgsDiv');
    
    if (scanProfileSelect && customArgsDiv) {
        scanProfileSelect.addEventListener('change', function() {
            if (this.value === 'custom') {
                customArgsDiv.style.display = 'block';
            } else {
                customArgsDiv.style.display = 'none';
            }
        });
        
        // Initial check
        if (scanProfileSelect.value === 'custom') {
            customArgsDiv.style.display = 'block';
        } else {
            customArgsDiv.style.display = 'none';
        }
    }
    
    // Schedule type selection in schedule form
    const scheduleTypeSelect = document.getElementById('scheduleTypeSelect');
    if (scheduleTypeSelect) {
        const scheduleOptions = document.querySelectorAll('.schedule-options');
        
        scheduleTypeSelect.addEventListener('change', function() {
            // Hide all options first
            scheduleOptions.forEach(function(option) {
                option.style.display = 'none';
            });
            
            // Show options based on selected schedule type
            const selectedOption = document.getElementById(`${this.value}Options`);
            if (selectedOption) {
                selectedOption.style.display = 'block';
            }
        });
        
        // Trigger change event to set initial state
        scheduleTypeSelect.dispatchEvent(new Event('change'));
    }
});
