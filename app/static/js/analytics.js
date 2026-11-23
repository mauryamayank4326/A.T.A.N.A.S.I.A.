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
});
