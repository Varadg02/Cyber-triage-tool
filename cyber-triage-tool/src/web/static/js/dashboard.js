document.addEventListener('DOMContentLoaded', function () {
    const caseId = document.querySelector('.case-id').textContent;

    fetch(`/api/report/${caseId}`)
        .then(response => response.json())
        .then(data => {
            const items = data.items;
            
            // Update summary cards
            const highEntropyCount = items.filter(item => item.flags.includes('high_entropy')).length;
            const executablesCount = items.filter(item => item.flags.includes('executable')).length;
            const yaraMatchesCount = items.filter(item => item.flags.includes('yara_match')).length;

            document.getElementById('high-entropy-count').textContent = highEntropyCount;
            document.getElementById('executables-count').textContent = executablesCount;
            document.getElementById('yara-matches-count').textContent = yaraMatchesCount;

            // Populate findings table
            const tableBody = document.getElementById('findings-table-body');
            items.forEach(item => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${item.path}</td>
                    <td><code>${item.hashes.sha256.substring(0, 12)}...</code></td>
                    <td>${item.entropy}</td>
                    <td>${item.flags.join(', ')}</td>
                `;
                tableBody.appendChild(row);
            });

            // Findings by Type Chart
            new Chart(document.getElementById('findings-chart'), {
                type: 'doughnut',
                data: {
                    labels: ['High Entropy', 'Executables', 'YARA Matches'],
                    datasets: [{
                        data: [highEntropyCount, executablesCount, yaraMatchesCount],
                        backgroundColor: ['#dc3545', '#ffc107', '#28a745']
                    }]
                }
            });

            // Entropy Distribution Chart
            new Chart(document.getElementById('entropy-chart'), {
                type: 'bar',
                data: {
                    labels: items.map(item => item.path.split('\\').pop()),
                    datasets: [{
                        label: 'Entropy',
                        data: items.map(item => item.entropy),
                        backgroundColor: 'rgba(0, 123, 255, 0.5)'
                    }]
                },
                options: {
                    scales: {
                        x: { display: false }
                    }
                }
            });
        });
});