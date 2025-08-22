// Configuration for the EAS Attestor application
// BUILD_TIME_CONFIG_INJECTION
window.EAS_CONFIG = {
    // GitHub URLs
    github: {
        domain: 'github.com',
        baseUrl: 'https://github.com',
        gistUrl: 'https://gist.github.com',
        apiUrl: 'https://api.github.com'
    },
    
    // Project URLs (can be overridden for different deployments)
    project: {
        repository: 'https://github.com/allenday/contributor-attestation-service',
        documentation: 'https://github.com/allendy/contributor-attestation-service/blob/main/README.md'
    },
    
    // EAS Contract addresses on Base networks
    contracts: {
        'base-sepolia': {
            eas: '0x4200000000000000000000000000000000000021',
            schemaRegistry: '0x4200000000000000000000000000000000000020'
        },
        'base': {
            eas: '0x4200000000000000000000000000000000000021', 
            schemaRegistry: '0x4200000000000000000000000000000000000020'
        }
    },
    
    // Chain IDs
    chainIds: {
        'base-sepolia': 84532,
        'base': 8453
    },
    
    // Schema UIDs loaded dynamically from deployment configs
    
    // Our known validator address (properly checksummed)
    validatorAddress: "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
    
    // API endpoints
    api: {
        graphql: {
            'base-sepolia': 'https://base-sepolia.easscan.org/graphql',
            'base': 'https://base.easscan.org/graphql'
        },
        validator: {
            local: 'http://localhost:6001',
            getEndpoint: function() {
                // Check for environment-specific override (set via build/deployment)
                if (window.EAS_VALIDATOR_URL) {
                    return window.EAS_VALIDATOR_URL;
                }
                
                // Check if we're in local development
                if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
                    return this.local;
                }
                
                // For staging/production, use same origin (validator serves on same host)
                return window.location.origin;
            }
        }
    }
};