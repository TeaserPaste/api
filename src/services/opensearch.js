const { Client } = require('@opensearch-project/opensearch');

let osClient = null;
if (process.env.OPENSEARCH_HOST && process.env.OPENSEARCH_USER && process.env.OPENSEARCH_PASSWORD) {
    const opensearchNode = `${process.env.OPENSEARCH_SCHEME || 'https'}://${process.env.OPENSEARCH_HOST}:${process.env.OPENSEARCH_PORT || '443'}`;
    const opensearchAuth = {
        username: process.env.OPENSEARCH_USER,
        password: process.env.OPENSEARCH_PASSWORD,
    };

    try {
        osClient = new Client({
            node: opensearchNode,
            auth: opensearchAuth,
            ssl: {
                rejectUnauthorized: process.env.NODE_ENV === 'production',
            },
        });
        console.log(`OpenSearch client initialized for node: ${opensearchNode}`);
        osClient.ping()
            .then(response => console.log('OpenSearch cluster ping successful.'))
            .catch(error => console.warn('OpenSearch cluster ping failed:', error.message));
    } catch (e) {
        console.error("❌ Failed to initialize OpenSearch client:", e.message);
    }
} else {
    console.warn("⚠️ OpenSearch environment variables (HOST, USER, PASSWORD) not set. Search functionality will be disabled.");
}

module.exports = { osClient };
