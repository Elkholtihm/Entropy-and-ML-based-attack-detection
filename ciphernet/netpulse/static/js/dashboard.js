// Dashboard JavaScript for Network Monitoring Application
// Global variables for charts and data
let charts = {};
let updateInterval;
let isStreaming = false;

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    setupEventListeners();
    startDataStream();
});

// Initialize all dashboard components
function initializeDashboard() {
    initializeCharts();
    updateDashboardCards();
    console.log('Dashboard initialized successfully');
}

// Setup event listeners for filters and controls
function setupEventListeners() {
    // Stream toggle
    const streamToggle = document.getElementById('stream-toggle');
    if (streamToggle) {
        streamToggle.addEventListener('change', function() {
            isStreaming = this.checked;
            if (isStreaming) {
                startDataStream();
            } else {
                stopDataStream();
            }
        });
    }

    // Filter event listeners
    const trafficFilter = document.getElementById('filter-traffic');
    const alertFilter = document.getElementById('filter-alert');
    
    if (trafficFilter) {
        trafficFilter.addEventListener('change', applyFilters);
    }
    
    if (alertFilter) {
        alertFilter.addEventListener('change', applyFilters);
    }
}

// Initialize all charts
function initializeCharts() {
    // DDOS Entropy Chart
    initChart('ddos-entropy-value-chart', 'DDOS Entropy', 'line', '#ff6384');
    
    // PortScan Entropy Chart
    initChart('portscan-entropy-value-chart', 'PortScan Entropy', 'line', '#36a2eb');
    
    // Hulk Entropy Chart
    initChart('hulk-entropy-value-chart', 'Hulk Entropy', 'line', '#cc65fe');
    
    // SlowHTTP Test Entropy Chart
    initChart('slowhttptest-entropy-value-chart', 'SlowHTTP Entropy', 'line', '#ffce56');
    
    // Huffman State Chart
    initChart('huffman-stat-chart', 'Huffman State', 'bar', '#4bc0c0');
    
    // Mutual Information Chart
    initChart('mutual-info-chart-2', 'Mutual Information', 'line', '#9966ff');
}

// Initialize individual chart
function initChart(canvasId, label, type, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) {
        console.warn(`Canvas with id ${canvasId} not found`);
        return;
    }

    const ctx = canvas.getContext('2d');
    
    const config = {
        type: type,
        data: {
            labels: generateTimeLabels(),
            datasets: [{
                label: label,
                data: generateRandomData(),
                borderColor: color,
                backgroundColor: color + '20',
                tension: 0.4,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: '#e0e0e0'
                    }
                },
                x: {
                    grid: {
                        color: '#e0e0e0'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            },
            elements: {
                point: {
                    radius: 3
                }
            }
        }
    };

    charts[canvasId] = new Chart(ctx, config);
}

// Generate time labels for charts
function generateTimeLabels() {
    const labels = [];
    const now = new Date();
    for (let i = 9; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60000);
        labels.push(time.toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit' 
        }));
    }
    return labels;
}

// Generate random data for demo purposes
function generateRandomData() {
    return Array.from({length: 10}, () => Math.floor(Math.random() * 100));
}

// Update dashboard cards with current values
function updateDashboardCards() {
    const cards = {
        'ddos-entropy-value': Math.floor(Math.random() * 1000) + ' bits',
        'portscan-entropy-value': Math.floor(Math.random() * 1000) + ' bits',
        'hulk-entropy-value': Math.floor(Math.random() * 1000) + ' bits',
        'slowhttptest-entropy-value': Math.floor(Math.random() * 1000) + ' bits',
        'packet-rate-value': Math.floor(Math.random() * 10000)
    };

    Object.keys(cards).forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = cards[id];
        }
    });
}

// Start real-time data streaming
function startDataStream() {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
    
    updateInterval = setInterval(() => {
        updateCharts();
        updateDashboardCards();
    }, 5000); // Update every 5 seconds
    
    console.log('Data stream started');
}

// Stop data streaming
function stopDataStream() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
    console.log('Data stream stopped');
}

// Update all charts with new data
function updateCharts() {
    Object.keys(charts).forEach(chartId => {
        const chart = charts[chartId];
        if (chart) {
            // Add new data point
            const newData = Math.floor(Math.random() * 100);
            const newTime = new Date().toLocaleTimeString('en-US', { 
                hour12: false, 
                hour: '2-digit', 
                minute: '2-digit' 
            });

            // Remove first data point and add new one
            chart.data.labels.shift();
            chart.data.labels.push(newTime);
            chart.data.datasets[0].data.shift();
            chart.data.datasets[0].data.push(newData);

            chart.update('none'); // Update without animation for performance
        }
    });
}

// Apply filters to data
function applyFilters() {
    const trafficFilter = document.getElementById('filter-traffic').value;
    const alertFilter = document.getElementById('filter-alert').value;
    
    console.log('Applying filters:', { trafficFilter, alertFilter });
    
    // Filter logic would go here
    // For now, just log the filter values
    
    // You would typically:
    // 1. Filter your data based on selected criteria
    // 2. Update charts with filtered data
    // 3. Update dashboard cards with filtered metrics
}

// Fetch data from backend API
async function fetchDashboardData() {
    try {
        const response = await fetch('/api/dashboard-data/');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        return null;
    }
}

// Update dashboard with real data from backend
async function updateWithRealData() {
    const data = await fetchDashboardData();
    if (data) {
        // Update cards with real data
        if (data.entropy_data) {
            document.getElementById('ddos-entropy-value').textContent = data.entropy_data.ddos + ' bits';
            document.getElementById('portscan-entropy-value').textContent = data.entropy_data.portscan + ' bits';
            document.getElementById('hulk-entropy-value').textContent = data.entropy_data.hulk + ' bits';
            document.getElementById('slowhttptest-entropy-value').textContent = data.entropy_data.slowhttp + ' bits';
        }
        
        if (data.packet_rate) {
            document.getElementById('packet-rate-value').textContent = data.packet_rate;
        }
        
        // Update charts with real data
        if (data.chart_data) {
            updateChartsWithRealData(data.chart_data);
        }
    }
}

// Update charts with real data from backend
function updateChartsWithRealData(chartData) {
    Object.keys(chartData).forEach(chartKey => {
        const chartId = chartKey + '-chart';
        if (charts[chartId] && chartData[chartKey]) {
            const chart = charts[chartId];
            chart.data.labels = chartData[chartKey].labels || generateTimeLabels();
            chart.data.datasets[0].data = chartData[chartKey].data || generateRandomData();
            chart.update();
        }
    });
}

// Handle errors gracefully
window.addEventListener('error', function(event) {
    console.error('Dashboard error:', event.error);
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    stopDataStream();
});

// Export functions for potential use in other scripts
window.dashboardFunctions = {
    startDataStream,
    stopDataStream,
    updateDashboardCards,
    updateCharts,
    fetchDashboardData
};