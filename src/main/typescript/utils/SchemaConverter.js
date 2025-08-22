/**
 * SchemaConverter - Universal converter between JSON, Proto, and Ethereum ABI formats
 * 
 * This utility class handles all serialization/deserialization between:
 * - JSON (frontend/API format)
 * - Proto (gRPC binary format) 
 * - Ethereum ABI (on-chain encoded format)
 * 
 * Common patterns:
 * - Writing: JSON => Ethereum ABI (for creating attestations)
 * - Reading: Ethereum ABI => Proto (for transaction decoding)
 * - Querying: JSON => Proto (for EAS GraphQL queries)
 */

import { ethers } from 'ethers';
import fs from 'fs';

class SchemaConverter {
    constructor() {
        this.schemas = {};
        this.deployments = {};
        this.typeMapping = new Map();
        this.loadSchemas();
        this.initializeTypeMappings();
    }

    /**
     * Load schema definitions and deployments from configuration files
     */
    loadSchemas() {
        try {
            // Load schema definitions
            const schemaDefPaths = [
                '/app/html/json/attestor/v1/attestor.json',
                '/app/html/dist/json/attestor/v1/attestor.json',
                './src/main/json/attestor/v1/attestor.json'
            ];
            
            let schemaDefPath = null;
            for (const p of schemaDefPaths) {
                if (fs.existsSync(p)) {
                    schemaDefPath = p;
                    break;
                }
            }
            
            // Load schema deployments (UIDs)
            const schemaDeployPaths = [
                '/app/html/config/schemas.json',
                '/app/config/schemas.json',
                './src/main/config/schemas.json'
            ];
            
            let schemaDeployPath = null;
            for (const p of schemaDeployPaths) {
                if (fs.existsSync(p)) {
                    schemaDeployPath = p;
                    break;
                }
            }
            
            if (schemaDefPath && schemaDeployPath) {
                this.schemas = JSON.parse(fs.readFileSync(schemaDefPath, 'utf8')).schemas;
                this.deployments = JSON.parse(fs.readFileSync(schemaDeployPath, 'utf8')).deployments;
                console.log('📋 SchemaConverter: Loaded schemas:', Object.keys(this.schemas));
            } else {
                console.warn('⚠️  SchemaConverter: Schema config not found');
            }
        } catch (error) {
            console.error('❌ SchemaConverter: Failed to load schemas:', error.message);
        }
    }

    /**
     * Initialize type mappings between different formats
     */
    initializeTypeMappings() {
        // JSON field name to Proto field name mappings (camelCase <=> snake_case)
        this.jsonToProtoField = new Map([
            ['ethereumAddress', 'ethereum_address'],
            ['proofUrl', 'proof_url'],
            ['registrantSignature', 'registrant_signature'],
            ['validationSignature', 'validation_signature'],
            ['identityAttestationUid', 'identity_attestation_uid'],
            ['repositoryRegistrationUid', 'repository_registration_uid'],
            ['eventType', 'event_type'],
            ['commitHash', 'commit_hash'],
            ['linkedIssueUids', 'linked_issue_uids'],
            ['reviewedPrUid', 'reviewed_pr_uid']
        ]);

        // Reverse mapping
        this.protoToJsonField = new Map();
        for (const [json, proto] of this.jsonToProtoField.entries()) {
            this.protoToJsonField.set(proto, json);
        }

        // Ethereum ABI type to Proto/JSON type mappings
        this.abiTypeMapping = new Map([
            ['string', 'string'],
            ['address', 'string'], // Addresses are strings in JSON/Proto
            ['bytes', 'bytes'],
            ['bytes32', 'bytes'],
            ['uint256', 'uint64'], // Use uint64 for large numbers in Proto
            ['uint32', 'uint32'],
            ['bool', 'bool'],
            ['bytes32[]', 'repeated bytes']
        ]);

        // Enum value mappings (for converting between string and integer representations)
        this.enumMappings = {
            IssueEvent: {
                'ISSUE_EVENT_UNKNOWN': 0,
                'ISSUE_EVENT_OPENED': 1,
                'ISSUE_EVENT_RESOLVED': 2
            },
            PullRequestEvent: {
                'PR_EVENT_UNKNOWN': 0,
                'PR_EVENT_OPENED': 1,
                'PR_EVENT_MERGED': 2,
                'PR_EVENT_CLOSED': 3
            },
            ReviewEvent: {
                'REVIEW_EVENT_UNKNOWN': 0,
                'REVIEW_EVENT_APPROVED': 1,
                'REVIEW_EVENT_CHANGES_REQUESTED': 2
            }
        };

        // Reverse enum mappings (integer to string)
        this.reverseEnumMappings = {};
        for (const [enumName, mapping] of Object.entries(this.enumMappings)) {
            this.reverseEnumMappings[enumName] = {};
            for (const [stringValue, intValue] of Object.entries(mapping)) {
                this.reverseEnumMappings[enumName][intValue] = stringValue;
            }
        }
    }

    /**
     * Parse schema definition string into field metadata
     * @param {string} definition - Schema definition (e.g., "string domain,address registrant,bytes signature")
     * @returns {Array} - Array of field metadata objects
     */
    parseSchemaDefinition(definition) {
        return definition.split(',').map(field => {
            const [type, name] = field.trim().split(' ');
            return {
                name: name,
                type: type,
                isArray: type.includes('[]'),
                baseType: type.replace('[]', '')
            };
        });
    }

    /**
     * Get schema metadata by key
     * @param {string} schemaKey - Schema identifier (e.g., 'identity', 'repository-registration')
     * @returns {Object} - Schema metadata including UID, fields, etc.
     */
    getSchemaMetadata(schemaKey) {
        const schema = this.schemas[schemaKey];
        if (!schema) {
            throw new Error(`Schema '${schemaKey}' not found`);
        }

        const deployment = this.deployments.find(d => d.contractName === schema.name);
        if (!deployment) {
            throw new Error(`Deployment for schema '${schemaKey}' not found`);
        }

        const fields = this.parseSchemaDefinition(schema.definition);

        return {
            key: schemaKey,
            name: schema.name,
            description: schema.description,
            uid: deployment.contractAddress,
            definition: schema.definition,
            fields: fields
        };
    }

    /**
     * Convert field name between JSON and Proto formats
     * @param {string} fieldName - Field name to convert
     * @param {string} fromFormat - Source format ('json' or 'proto')
     * @returns {string} - Converted field name
     */
    convertFieldName(fieldName, fromFormat) {
        if (fromFormat === 'json') {
            return this.jsonToProtoField.get(fieldName) || fieldName;
        } else if (fromFormat === 'proto') {
            return this.protoToJsonField.get(fieldName) || fieldName;
        }
        return fieldName;
    }

    /**
     * Convert enum string to integer value
     * @param {string} enumType - Enum type name (e.g., 'IssueEvent')
     * @param {string} stringValue - String value (e.g., 'ISSUE_EVENT_OPENED')
     * @returns {number} - Integer value
     */
    enumStringToInt(enumType, stringValue) {
        const mapping = this.enumMappings[enumType];
        if (!mapping) {
            throw new Error(`Unknown enum type: ${enumType}`);
        }
        
        const intValue = mapping[stringValue];
        if (intValue === undefined) {
            throw new Error(`Unknown enum value '${stringValue}' for type '${enumType}'`);
        }
        
        return intValue;
    }

    /**
     * Convert enum integer to string value
     * @param {string} enumType - Enum type name (e.g., 'IssueEvent')
     * @param {number} intValue - Integer value
     * @returns {string} - String value
     */
    enumIntToString(enumType, intValue) {
        const mapping = this.reverseEnumMappings[enumType];
        if (!mapping) {
            throw new Error(`Unknown enum type: ${enumType}`);
        }
        
        const stringValue = mapping[intValue];
        if (!stringValue) {
            throw new Error(`Unknown enum value '${intValue}' for type '${enumType}'`);
        }
        
        return stringValue;
    }

    /**
     * Convert JSON data to Ethereum ABI encoded format
     * @param {string} schemaKey - Schema identifier
     * @param {Object} jsonData - JSON data object
     * @returns {Object} - {schemaUID, encodedData, types, values}
     */
    jsonToEthereum(schemaKey, jsonData) {
        const metadata = this.getSchemaMetadata(schemaKey);
        
        console.log(`📋 Converting JSON to Ethereum for schema '${schemaKey}'`);

        // Extract types and values in schema field order
        const types = [];
        const values = [];

        for (const field of metadata.fields) {
            let value = jsonData[field.name];
            
            if (value === undefined) {
                // Try alternative field name formats
                const altFieldName = this.convertFieldName(field.name, 'proto');
                value = jsonData[altFieldName];
            }
            
            if (value === undefined) {
                throw new Error(`Missing required field '${field.name}' for schema '${schemaKey}'`);
            }

            types.push(field.type);
            
            // Keep enum as string for on-chain clarity (no conversion needed)
            // The schema defines `string eventType` so we store strings on-chain

            values.push(value);
        }

        console.log('📋 Schema types:', types);
        console.log('📋 Schema values:', values);

        const encodedData = ethers.AbiCoder.defaultAbiCoder().encode(types, values);

        return {
            schemaUID: metadata.uid,
            encodedData: encodedData,
            types: types,
            values: values,
            metadata: metadata
        };
    }

    /**
     * Convert Ethereum ABI encoded data to JSON format
     * @param {string} schemaKey - Schema identifier
     * @param {string} encodedData - Hex-encoded ABI data
     * @returns {Object} - Decoded JSON object
     */
    ethereumToJson(schemaKey, encodedData) {
        const metadata = this.getSchemaMetadata(schemaKey);
        
        console.log(`📋 Converting Ethereum to JSON for schema '${schemaKey}'`);

        const types = metadata.fields.map(f => f.type);
        const decodedValues = ethers.AbiCoder.defaultAbiCoder().decode(types, encodedData);

        const jsonData = {};

        for (let i = 0; i < metadata.fields.length; i++) {
            const field = metadata.fields[i];
            let value = decodedValues[i];

            // eventType is stored as string on-chain, no conversion needed

            // Handle BigInt conversion to string
            if (typeof value === 'bigint') {
                value = value.toString();
            }

            jsonData[field.name] = value;
        }

        console.log('📋 Decoded JSON data:', jsonData);

        return jsonData;
    }

    /**
     * Convert JSON data to Proto format (camelCase to snake_case, etc.)
     * @param {string} schemaKey - Schema identifier
     * @param {Object} jsonData - JSON data object
     * @returns {Object} - Proto-formatted object
     */
    jsonToProto(schemaKey, jsonData) {
        const metadata = this.getSchemaMetadata(schemaKey);
        const protoData = {};

        console.log(`📋 Converting JSON to Proto for schema '${schemaKey}'`);

        for (const field of metadata.fields) {
            let value = jsonData[field.name];
            
            if (value !== undefined) {
                const protoFieldName = this.convertFieldName(field.name, 'json');
                protoData[protoFieldName] = value;
            }
        }

        return protoData;
    }

    /**
     * Convert Proto data to JSON format (snake_case to camelCase, etc.)
     * @param {string} schemaKey - Schema identifier
     * @param {Object} protoData - Proto data object
     * @returns {Object} - JSON-formatted object
     */
    protoToJson(schemaKey, protoData) {
        const metadata = this.getSchemaMetadata(schemaKey);
        const jsonData = {};

        console.log(`📋 Converting Proto to JSON for schema '${schemaKey}'`);

        for (const [protoKey, value] of Object.entries(protoData)) {
            if (value !== undefined) {
                const jsonFieldName = this.convertFieldName(protoKey, 'proto');
                jsonData[jsonFieldName] = value;
            }
        }

        return jsonData;
    }

    /**
     * Convert EAS GraphQL decoded data to JSON format
     * @param {string} schemaKey - Schema identifier
     * @param {Array} decodedDataJson - Decoded data from EAS GraphQL
     * @returns {Object} - JSON object
     */
    easGraphqlToJson(schemaKey, decodedDataJson) {
        const metadata = this.getSchemaMetadata(schemaKey);
        const jsonData = {};

        console.log(`📋 Converting EAS GraphQL to JSON for schema '${schemaKey}'`);

        // EAS GraphQL format: [{ name: "fieldName", value: { value: actualValue, type: "string" } }]
        for (const item of decodedDataJson) {
            const fieldName = item.name;
            const fieldValue = item.value?.value;
            
            if (fieldValue !== undefined) {
                // eventType is stored as string, no conversion needed
                let value = fieldValue;
                
                jsonData[fieldName] = value;
            }
        }

        return jsonData;
    }

    /**
     * Validate JSON data against schema requirements
     * @param {string} schemaKey - Schema identifier
     * @param {Object} jsonData - JSON data to validate
     * @returns {Object} - {isValid, errors, warnings}
     */
    validateJsonData(schemaKey, jsonData) {
        const metadata = this.getSchemaMetadata(schemaKey);
        const errors = [];
        const warnings = [];

        // Check required fields
        for (const field of metadata.fields) {
            const value = jsonData[field.name];
            
            if (value === undefined || value === null || value === '') {
                // Try alternative field name
                const altFieldName = this.convertFieldName(field.name, 'proto');
                const altValue = jsonData[altFieldName];
                
                if (altValue === undefined || altValue === null || altValue === '') {
                    errors.push(`Missing required field: ${field.name}`);
                }
            }
        }

        // Type validation
        for (const [fieldName, value] of Object.entries(jsonData)) {
            const field = metadata.fields.find(f => f.name === fieldName);
            if (!field) continue;

            if (field.type === 'address' && typeof value === 'string') {
                if (!ethers.isAddress(value)) {
                    errors.push(`Invalid Ethereum address format: ${fieldName}`);
                }
            }

            if (field.type.startsWith('bytes') && typeof value === 'string') {
                if (!value.startsWith('0x')) {
                    warnings.push(`Bytes field ${fieldName} should be hex-encoded (0x...)`);
                }
            }
        }

        return {
            isValid: errors.length === 0,
            errors: errors,
            warnings: warnings
        };
    }

    /**
     * Get all available schema keys
     * @returns {Array} - Array of schema keys
     */
    getAvailableSchemas() {
        return Object.keys(this.schemas);
    }

    /**
     * Get schema UID by key
     * @param {string} schemaKey - Schema identifier
     * @returns {string} - Schema UID (contract address)
     */
    getSchemaUID(schemaKey) {
        const metadata = this.getSchemaMetadata(schemaKey);
        return metadata.uid;
    }

    /**
     * Find schema key by UID
     * @param {string} schemaUID - Schema UID (contract address)
     * @returns {string} - Schema key
     */
    findSchemaByUID(schemaUID) {
        const deployment = this.deployments.find(d => d.contractAddress === schemaUID);
        if (!deployment) {
            throw new Error(`No deployment found for schema UID: ${schemaUID}`);
        }

        const schemaKey = Object.keys(this.schemas).find(key => 
            this.schemas[key].name === deployment.contractName
        );

        if (!schemaKey) {
            throw new Error(`No schema definition found for contract: ${deployment.contractName}`);
        }

        return schemaKey;
    }

    /**
     * Create attestation data structure for EAS contract
     * @param {string} schemaKey - Schema identifier
     * @param {Object} jsonData - JSON data
     * @param {string} recipient - Recipient address (optional)
     * @param {Object} options - Additional options (expiration, revocable, etc.)
     * @returns {Object} - EAS attestation request structure
     */
    createAttestationRequest(schemaKey, jsonData, recipient = null, options = {}) {
        const { schemaUID, encodedData } = this.jsonToEthereum(schemaKey, jsonData);

        return {
            schema: schemaUID,
            data: {
                recipient: recipient || (() => { throw new Error('CRITICAL: Recipient address required for attestation - cannot use zero address'); })(),
                expirationTime: options.expirationTime || 0,
                revocable: options.revocable !== false, // Default to true
                refUID: options.refUID || (() => { throw new Error('CRITICAL: RefUID must be explicitly provided - cannot use zero UID fallback'); })(),
                data: encodedData,
                value: options.value || 0
            }
        };
    }
}

export default SchemaConverter;