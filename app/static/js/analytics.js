"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const dataElement = document.getElementById("analytics-data");

    if (!dataElement || typeof Chart === "undefined") {
        return;
    }

    let analytics;

    try {
        analytics = JSON.parse(dataElement.textContent);
    } catch {
        console.error("Unable to parse analytics data.");
        return;
    }

    const statusCanvas = document.getElementById("scanStatusChart");
    const assetCanvas = document.getElementById("assetDistributionChart");
    const portCanvas = document.getElementById("portDistributionChart");
    const serviceCanvas = document.getElementById("serviceDistributionChart");

    if (statusCanvas) {
        const statuses = analytics.scan_status_distribution ?? [];

        new Chart(statusCanvas, {
            type: "doughnut",
            data: {
                labels: statuses.map(item => item.status),
                datasets: [{
                    label: "Scans",
                    data: statuses.map(item => item.count),
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                    },
                },
            },
        });
    }

    if (assetCanvas) {
        const assets = analytics.asset_distribution ?? [];

        new Chart(assetCanvas, {
            type: "bar",
            data: {
                labels: assets.map(item => item.asset_type),
                datasets: [{
                    label: "Records",
                    data: assets.map(item => item.count),
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                        },
                    },
                },
            },
        });
    }

    if (portCanvas) {
        const portData = analytics.port_distribution ?? [];

        new Chart(portCanvas, {
            type: "bar",
            data: {
                labels: portData.map(item => String(item.port)),
                datasets: [{
                    label: "Exposed Port Observations",
                    data: portData.map(item => item.count),
                }],
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                        },
                    },
                },
            },
        });
    }

    if (serviceCanvas) {
        const serviceData = analytics.service_distribution ?? [];

        new Chart(serviceCanvas, {
            type: "doughnut",
            data: {
                labels: serviceData.map(item => item.service_name),
                datasets: [{
                    label: "Service Observations",
                    data: serviceData.map(item => item.count),
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
            },
        });
    }
});
