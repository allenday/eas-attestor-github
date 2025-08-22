/**
 * AttestService REST Implementation - Direct CommonJS version
 * Implementation of the AttestService interface for REST endpoints
 */

const Service = require('./Service');
const fs = require('fs');
const path = require('path');

class AttestServiceImpl {
    constructor() {
        // Load schema data from JSON file
        this.schemas = this.loadSchemas();
    }

    loadSchemas() {
        try {
            const schemaPath = path.join(__dirname, '../../json/attestor/v1/attestor.json');
            const schemaData = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
            return schemaData.schemas;
        } catch (error) {
            console.error('❌ Failed to load schemas:', error.message);
            // Fallback to schema-compliant definitions
            return {
                "identity": {
                    name: "Identity",
                    definition: "string domain,string identifier,address ethereumAddress,string proofUrl,address validator,bytes validationSignature",
                    description: "Domain identity verification"
                },
                "repository-registration": {
                    name: "RepositoryRegistration",
                    definition: "string domain,string path,address registrant,bytes registrantSignature,string proofUrl,address validator,bytes validationSignature",
                    description: "Repository registration for contribution monitoring"
                }
            };
        }
    }

    async createAttestation({ body }) {
        try {
            const { schema_type, data, recipient, revocable, expiration_time } = body;
            
            console.log('📝 Creating attestation:', {
                schema_type,
                recipient,
                expiration_time,
                revocable
            });

            // Mock attestation creation
            const mockAttestationUid = `0x${Math.random().toString(16).substr(2, 64)}`;
            const mockTxHash = `0x${Math.random().toString(16).substr(2, 64)}`;

            return {
                attestation_uid: mockAttestationUid,
                transaction_hash: mockTxHash,
                attester: ethers.getAddress(process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || 
                                          process.env.DEPLOY_CLOUD_PROD_VALIDATOR_ADDRESS || 
                                          '0x0000000000000000000000000000000000000000')
            };

        } catch (error) {
            console.error('❌ createAttestation failed:', error.message);
            throw error;
        }
    }

    async getSchemas() {
        try {
            console.log('📋 Retrieved schemas');
            
            return {
                schemas: this.schemas,
                deployments: [
                    {
                        contract_name: "EAS",
                        contract_address: "0x4200000000000000000000000000000000000021"
                    }
                ]
            };

        } catch (error) {
            console.error('❌ getSchemas failed:', error.message);
            throw error;
        }
    }

    async getSchema({ path: { schema_type } }) {
        try {
            const schema = this.schemas[schema_type];
            
            if (!schema) {
                throw new Error(`Schema not found: ${schema_type}`);
            }

            console.log('📋 Retrieved schema:', schema_type);

            return {
                schema: schema,
                deployment: {
                    contract_name: "EAS",
                    contract_address: "0x4200000000000000000000000000000000000021"
                }
            };

        } catch (error) {
            console.error('❌ getSchema failed:', error.message);
            throw error;
        }
    }
}

const attestServiceInstance = new AttestServiceImpl();

const createAttestation = ({ body }) => new Promise(async (resolve, reject) => {
    try {
        const result = await attestServiceInstance.createAttestation({ body });
        resolve(Service.successResponse(result));
    } catch (e) {
        reject(Service.rejectResponse(
            e.message || 'Invalid input',
            e.status || 500,
        ));
    }
});

const getSchemas = () => new Promise(async (resolve, reject) => {
    try {
        const result = await attestServiceInstance.getSchemas();
        resolve(Service.successResponse(result));
    } catch (e) {
        reject(Service.rejectResponse(
            e.message || 'Invalid input',
            e.status || 500,
        ));
    }
});

const getSchema = ({ path }) => new Promise(async (resolve, reject) => {
    try {
        const result = await attestServiceInstance.getSchema({ path });
        resolve(Service.successResponse(result));
    } catch (e) {
        reject(Service.rejectResponse(
            e.message || 'Invalid input',
            e.status || 500,
        ));
    }
});

module.exports = {
    createAttestation,
    getSchemas,
    getSchema,
};