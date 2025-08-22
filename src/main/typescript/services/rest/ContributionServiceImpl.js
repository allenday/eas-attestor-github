/**
 * ContributionService REST Implementation - Direct CommonJS version
 * Implementation of the ContributionService interface for REST endpoints
 */

const Service = require('../../../generated/server/services/Service');
const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');
const { EAS, SchemaEncoder } = require('@ethereum-attestation-service/eas-sdk');

class ContributionServiceImpl {
    constructor() {
        // Mock data storage
        this.repositories = new Map();
        this.identities = new Map();
        this.contributions = [];
        this.webhookSecrets = new Map();
        
        // Initialize EAS configuration
        this.mockTransactions = process.env.MOCK_TRANSACTIONS === '1';
        this.loadSchemaConfig();
        this.initializeEAS();
    }

    loadSchemaConfig() {
        try {
            // Load schema configuration
            const configPath = path.join(__dirname, '../../../main/config/schemas.json');
            const schemaConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            
            this.network = schemaConfig.network;
            this.easContractAddress = schemaConfig.eas_contract;
            
            // Map schema UIDs by contract name
            this.schemaUIDs = {};
            schemaConfig.deployments.forEach(deployment => {
                this.schemaUIDs[deployment.contractName] = deployment.contractAddress;
            });
            
            // Load schema definitions from attestor.json
            const attestorPath = path.join(__dirname, '../../../main/json/attestor/v1/attestor.json');
            const attestorConfig = JSON.parse(fs.readFileSync(attestorPath, 'utf8'));
            
            // Map schema definitions by schema name
            this.schemaDefinitions = {};
            Object.values(attestorConfig.schemas).forEach(schema => {
                this.schemaDefinitions[schema.name] = schema.definition;
            });
            
            console.log(`📋 Loaded schema config for ${this.network}`);
            console.log('📋 Available schemas:', Object.keys(this.schemaUIDs));
            console.log('📋 Schema definitions loaded:', Object.keys(this.schemaDefinitions));
            
        } catch (error) {
            console.error('❌ Failed to load schema config:', error.message);
            throw new Error(`Schema configuration loading failed: ${error.message}. Service cannot start without valid configuration.`);
        }
    }

    initializeEAS() {
        if (this.mockTransactions) {
            console.log('🧪 Using mock transactions (MOCK_TRANSACTIONS=1)');
            return;
        }

        // Initialize EAS for Base Sepolia
        const privateKey = process.env.DEPLOY_LOCAL_DEV_VALIDATOR_PRIVATE_KEY || 
                          process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY;
        
        if (!privateKey) {
            console.error('❌ No private key found for EAS transactions');
            this.mockTransactions = true;
            return;
        }

        try {
            // Base Sepolia configuration
            const rpcUrl = process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org';
            this.provider = new ethers.JsonRpcProvider(rpcUrl);
            this.wallet = new ethers.Wallet(privateKey, this.provider);
            
            // Initialize EAS SDK
            this.eas = new EAS(this.easContractAddress);
            this.eas.connect(this.wallet);
            
            this.SCHEMA_REGISTRY_ADDRESS = '0x4200000000000000000000000000000000000020'; // Base Sepolia schema registry
            
            // EAS GraphQL endpoint for dynamic identity lookups
            this.EAS_GRAPHQL_URL = this.network === 'base' 
                ? 'https://base.easscan.org/graphql' 
                : 'https://base-sepolia.easscan.org/graphql';
            
            // Cache for resolved identities to avoid repeated GraphQL calls
            this.identityCache = new Map();
            
            console.log('🌐 Initialized EAS SDK for Base Sepolia testnet');
            console.log('📝 Wallet address:', this.wallet.address);
            console.log('📋 EAS contract:', this.easContractAddress);
        } catch (error) {
            console.error('❌ Failed to initialize EAS:', error.message);
            this.mockTransactions = true;
        }
    }

    async registerRepository({ body }) {
        try {
            const { path, registrantSignature, registrant } = body;
            
            // Validate required fields
            if (!path || !registrantSignature || !registrant) {
                throw new Error('path, registrantSignature, and registrant are required');
            }
            
            console.log('📋 Registering repository:', path);

            // Generate proper 64-character mock attestation UID
            const attestationUid = ethers.hexlify(ethers.randomBytes(32));
            
            // Generate webhook secret
            const webhookSecret = `wh_${Math.random().toString(16).substr(2, 32)}`;
            
            // Store repository with schema-compliant field names
            this.repositories.set(path, {
                path,
                registrantSignature,
                registrant,
                attestationUid: attestationUid,
                webhookSecret: webhookSecret
            });
            
            this.webhookSecrets.set(path, webhookSecret);

            return {
                attestationUid: attestationUid,
                webhookSecret: webhookSecret
            };

        } catch (error) {
            console.error('❌ registerRepository failed:', error.message);
            throw error;
        }
    }

    async getWebhookSecret({ body }) {
        try {
            const { path } = body;
            
            const secret = this.webhookSecrets.get(path);
            const registered = this.repositories.has(path);

            return {
                webhookSecret: secret || '',
                registered: registered
            };

        } catch (error) {
            console.error('❌ getWebhookSecret failed:', error.message);
            throw error;
        }
    }

    async listRegisteredRepositories() {
        try {
            const repositories = Array.from(this.repositories.values());
            
            return {
                repositories: repositories
            };

        } catch (error) {
            console.error('❌ listRegisteredRepositories failed:', error.message);
            throw error;
        }
    }

    async validateGistContent(proofUrl, expectedIdentifier, expectedEthereumAddress) {
        try {
            console.log('🔍 Validating gist content:', proofUrl);
            
            // Parse gist URL to extract username and gist ID
            const gistMatch = proofUrl.match(/https:\/\/gist\.github\.com\/([^\/]+)\/([a-f0-9]+)/);
            if (!gistMatch) {
                throw new Error('Invalid gist URL format. Expected: https://gist.github.com/username/gist_id');
            }
            
            const [, username, gistId] = gistMatch;
            
            // CRITICAL VALIDATION: Check if gist URL username matches claimed identifier
            if (username !== expectedIdentifier) {
                throw new Error(`Gist URL username mismatch. Expected gist from user "${expectedIdentifier}", but URL is from user "${username}". The gist must be created by the user claiming the identity.`);
            }
            
            console.log(`✅ Gist URL username "${username}" matches claimed identifier "${expectedIdentifier}"`);
            
            // Try different approaches to get the raw content
            const possibleUrls = [
                // Direct raw URL for specific filename
                `https://gist.githubusercontent.com/${username}/${gistId}/raw/eas-identity-verification.json`,
                // Generic raw URL (gets the first file)
                `https://gist.githubusercontent.com/${username}/${gistId}/raw`,
                // GitHub API approach
                `https://api.github.com/gists/${gistId}`
            ];
            
            let gistContent = null;
            let fetchError = null;
            
            // Try the raw file approach first
            for (const url of possibleUrls.slice(0, 2)) {
                try {
                    console.log('📥 Fetching gist content from:', url);
                    const response = await fetch(url);
                    
                    if (response.ok) {
                        const content = await response.text();
                        console.log('📄 Raw gist content:', content.substring(0, 200) + '...');
                        
                        // Try to parse as JSON
                        try {
                            gistContent = JSON.parse(content);
                            console.log('✅ Successfully parsed gist JSON:', gistContent);
                            break;
                        } catch (parseError) {
                            console.log('⚠️ Content is not valid JSON, trying next URL...');
                            continue;
                        }
                    } else {
                        console.log(`⚠️ HTTP ${response.status} from ${url}, trying next approach...`);
                    }
                } catch (error) {
                    console.log(`⚠️ Error fetching from ${url}:`, error.message);
                    fetchError = error;
                }
            }
            
            // If raw approaches failed, try GitHub API
            if (!gistContent) {
                try {
                    const apiUrl = possibleUrls[2];
                    console.log('📥 Trying GitHub API approach:', apiUrl);
                    const response = await fetch(apiUrl);
                    
                    if (response.ok) {
                        const gistData = await response.json();
                        
                        // Find the JSON file in the gist
                        const files = gistData.files || {};
                        const jsonFile = Object.values(files).find(file => 
                            file.filename?.includes('.json') || 
                            file.filename === 'eas-identity-verification.json'
                        ) || Object.values(files)[0]; // fallback to first file
                        
                        if (jsonFile && jsonFile.content) {
                            console.log('📄 Found file content via API:', jsonFile.filename);
                            gistContent = JSON.parse(jsonFile.content);
                            console.log('✅ Successfully parsed gist JSON via API:', gistContent);
                        } else {
                            throw new Error('No JSON file found in gist');
                        }
                    } else {
                        throw new Error(`GitHub API returned ${response.status}: ${response.statusText}`);
                    }
                } catch (apiError) {
                    console.log('⚠️ GitHub API approach failed:', apiError.message);
                    fetchError = apiError;
                }
            }
            
            if (!gistContent) {
                throw new Error(`Failed to fetch gist content. Last error: ${fetchError?.message || 'Unknown error'}. Please ensure the gist is public and contains valid JSON.`);
            }
            
            // Validate the JSON schema
            const requiredFields = ['domain', 'identifier', 'registrant', 'registrantSignature'];
            const missingFields = requiredFields.filter(field => !(field in gistContent));
            
            if (missingFields.length > 0) {
                throw new Error(`Gist content missing required fields: ${missingFields.join(', ')}. Expected format: { "domain": "github.com", "identifier": "username", "registrant": "0x...", "registrantSignature": "0x..." }`);
            }
            
            // Validate field values
            if (gistContent.domain !== 'github.com') {
                throw new Error(`Invalid domain in gist. Expected: "github.com", found: "${gistContent.domain}"`);
            }
            
            if (gistContent.identifier !== expectedIdentifier) {
                throw new Error(`Identifier mismatch. Expected: "${expectedIdentifier}", found: "${gistContent.identifier}"`);
            }
            
            // Normalize addresses using ethers checksum before comparison
            // Handle potentially invalid checksums by converting to lowercase first
            const normalizedExpected = ethers.getAddress(expectedEthereumAddress);
            let normalizedFound;
            try {
                normalizedFound = ethers.getAddress(gistContent.registrant);
            } catch (error) {
                // If checksum is invalid, try with lowercase version
                try {
                    normalizedFound = ethers.getAddress(gistContent.registrant.toLowerCase());
                } catch (lowercaseError) {
                    throw new Error(`Invalid registrant address in gist: ${gistContent.registrant}`);
                }
            }
            if (normalizedFound !== normalizedExpected) {
                throw new Error(`Registrant address mismatch. Expected: "${normalizedExpected}", found: "${normalizedFound}"`);
            }
            
            // Validate the registrant signature in the gist content using normalized address
            const baseMessage = `${gistContent.domain}${gistContent.identifier}${normalizedFound}`;
            
            // Normalize gist signature format
            let normalizedGistSignature;
            try {
                normalizedGistSignature = ethers.Signature.from(gistContent.registrantSignature).serialized;
            } catch (error) {
                throw new Error(`Invalid gist signature format: ${error.message}`);
            }
            
            try {
                const recoveredAddress = ethers.verifyMessage(baseMessage, normalizedGistSignature);
                if (ethers.getAddress(recoveredAddress) !== normalizedFound) {
                    throw new Error(`Gist signature verification failed. Expected signature from ${normalizedFound}, but recovered ${ethers.getAddress(recoveredAddress)}`);
                }
                console.log(`✅ Gist registrant signature verified for ${ethers.getAddress(gistContent.registrant)}`);
            } catch (error) {
                throw new Error(`Invalid gist registrant signature: ${error.message}`);
            }
            
            console.log('✅ Gist content validation successful');
            return {
                valid: true,
                content: gistContent
            };
            
        } catch (error) {
            console.error('❌ Gist validation failed:', error.message);
            return {
                valid: false,
                error: error.message
            };
        }
    }

    async registerIdentity({ body }) {
        try {
            console.log('📥 registerIdentity called with body:', JSON.stringify(body, null, 2));
            
            if (!body) {
                throw new Error('Request body is required');
            }
            
            let { identifier, proofUrl, registrant, registrantSignature } = body;
            
            // Validate required fields with detailed error messages
            if (!identifier) {
                throw new Error('identifier is required - GitHub username must be provided');
            }
            if (!proofUrl) {
                throw new Error('proofUrl is required - Gist URL must be provided');
            }
            if (!registrant) {
                throw new Error('registrant is required - Ethereum address must be provided');
            }
            if (!registrantSignature) {
                throw new Error('registrantSignature is required - Registrant signature must be provided');
            }
            
            // Ensure proper checksum format for registrant address
            try {
                registrant = ethers.getAddress(registrant);
                console.log(`✅ Checksummed registrant address: ${registrant}`);
            } catch (error) {
                throw new Error(`Invalid registrant address format: ${error.message}`);
            }
            
            // Normalize the signature format to ensure consistent handling
            try {
                registrantSignature = ethers.Signature.from(registrantSignature).serialized;
                console.log(`✅ Normalized registrant signature: ${registrantSignature}`);
            } catch (error) {
                throw new Error(`Invalid registrant signature format: ${error.message}`);
            }
            
            // Validate field formats
            if (typeof identifier !== 'string' || identifier.trim().length === 0) {
                throw new Error('identifier must be a non-empty string');
            }
            if (typeof proofUrl !== 'string' || !proofUrl.includes('gist.github.com')) {
                throw new Error('proofUrl must be a valid GitHub gist URL');
            }
            if (typeof registrant !== 'string' || !registrant.startsWith('0x')) {
                throw new Error('registrant must be a valid Ethereum address starting with 0x');
            }
            if (typeof registrantSignature !== 'string' || (!registrantSignature.startsWith('0x') && registrantSignature.length < 64)) {
                throw new Error('registrantSignature must be a valid signature');
            }
            
            console.log(`👤 Registering identity: ${identifier} → ${registrant}`);
            
            // Validate gist content BEFORE creating attestation
            const gistValidation = await this.validateGistContent(proofUrl, identifier, registrant);
            if (!gistValidation.valid) {
                throw new Error(`Gist content validation failed: ${gistValidation.error}`);
            }
            
            console.log('✅ Gist content validated successfully');

            // CRITICAL: Verify the registrant signature of the payload
            // The payload that should be signed is: domain + identifier + registrant + proofUrl
            // Use normalized registrant address for consistent signature verification
            const payloadToVerify = `github.com${identifier}${registrant}${proofUrl}`;
            const messageHash = ethers.keccak256(ethers.toUtf8Bytes(payloadToVerify));
            
            try {
                const recoveredAddress = ethers.verifyMessage(payloadToVerify, registrantSignature);
                if (ethers.getAddress(recoveredAddress) !== ethers.getAddress(registrant)) {
                    throw new Error(`Registrant signature verification failed. Expected signature from ${ethers.getAddress(registrant)}, but recovered ${ethers.getAddress(recoveredAddress)}`);
                }
                console.log(`✅ Registrant signature verified for ${ethers.getAddress(registrant)}`);
            } catch (error) {
                throw new Error(`Invalid registrant signature: ${error.message}`);
            }

            // Generate real validator signature after successful verification
            if (!this.wallet) {
                throw new Error('Validator wallet not initialized - check private key configuration');
            }
            
            const validator = this.wallet.address;
            
            // Create proper validator signature of the verified identity data
            const validatorPayload = `VALIDATOR_ATTESTATION:${identifier}:${registrant}:${proofUrl}`;
            const validatorSignature = await this.wallet.signMessage(validatorPayload);
            
            let attestationUid, txHash = null;
            
            if (this.mockTransactions) {
                // Mock mode: Generate random UID
                attestationUid = ethers.hexlify(ethers.randomBytes(32));
                console.log('🧪 Mock transaction mode - no on-chain attestation created');
            } else {
                // Real mode: Create actual EAS attestation
                console.log('🔗 Creating real EAS attestation on Base Sepolia...');
                
                const identityResult = await this.createIdentityAttestation({
                    identifier,
                    registrant,
                    proofUrl,
                    registrantSignature,
                    validator,
                    validatorSignature
                });
                
                if (identityResult.success) {
                    attestationUid = identityResult.attestationUid;
                    txHash = identityResult.txHash;
                    console.log(`✅ EAS attestation created: ${attestationUid}`);
                    console.log(`🔗 Transaction: ${txHash}`);
                } else {
                    throw new Error(`Failed to create EAS attestation: ${identityResult.error}`);
                }
            }

            // Store identity using EAS schema field names (updated schema)
            const identityRecord = {
                domain: 'github.com',
                identifier,
                registrant,
                proofUrl,
                validator,
                registrantSignature,
                validatorSignature,
                attestationUid,
                gistContent: gistValidation.content // Store validated content
            };
            
            this.identities.set(identifier, identityRecord);

            const returnValue = {
                attestationUid,
                validatorSignature,
                validator,
                txHash
            };
            
            console.log('✅ registerIdentity returning:', JSON.stringify(returnValue, null, 2));
            
            // Validate return values are not undefined
            if (!returnValue.attestationUid || !returnValue.validatorSignature || !returnValue.validator) {
                console.error('⚠️  WARNING: Return values contain undefined:', returnValue);
                throw new Error('Internal error: Generated values are undefined');
            }
            
            return returnValue;

        } catch (error) {
            console.error('❌ registerIdentity failed:', error.message);
            throw error;
        }
    }

    async createIdentityAttestation({ identifier, registrant, proofUrl, registrantSignature, validator, validatorSignature }) {
        try {
            if (!this.eas || !this.wallet) {
                throw new Error('EAS not properly initialized');
            }

            // Get the Identity schema UID
            const identitySchemaUID = this.schemaUIDs.Identity;
            if (!identitySchemaUID) {
                throw new Error('Identity schema UID not found in configuration');
            }

            // Get the schema definition
            const schemaDefinition = this.schemaDefinitions.Identity;
            if (!schemaDefinition) {
                throw new Error('Identity schema definition not found');
            }

            console.log(`🔗 Creating EAS attestation for identity: ${identifier}`);
            console.log(`📝 Schema: Identity (${identitySchemaUID})`);
            console.log(`📝 Definition: ${schemaDefinition}`);

            // Encode identity data using SchemaEncoder
            const { SchemaEncoder } = require('@ethereum-attestation-service/eas-sdk');
            const schemaEncoder = new SchemaEncoder(schemaDefinition);
            
            // Ensure proper address checksums for EAS encoding
            const checksummedRegistrant = ethers.getAddress(registrant);
            const checksummedValidator = ethers.getAddress(validator);

            const encodedData = schemaEncoder.encodeData([
                { name: 'domain', value: 'github.com', type: 'string' },
                { name: 'identifier', value: identifier, type: 'string' },
                { name: 'registrant', value: checksummedRegistrant, type: 'address' },
                { name: 'proofUrl', value: proofUrl, type: 'string' },
                { name: 'validator', value: checksummedValidator, type: 'address' },
                { name: 'registrantSignature', value: registrantSignature, type: 'bytes' },
                { name: 'validatorSignature', value: validatorSignature, type: 'bytes' }
            ]);

            console.log('🔗 Submitting attestation to EAS contract...');

            // Submit attestation using EAS SDK
            const tx = await this.eas.attest({
                schema: identitySchemaUID,
                data: {
                    recipient: checksummedRegistrant, // The registrant receives the identity attestation
                    expirationTime: 0n, // No expiration
                    revocable: true,
                    refUID: '0x0000000000000000000000000000000000000000000000000000000000000000', // No reference
                    data: encodedData
                }
            });

            console.log('⏳ Transaction submitted:', tx);
            
            // Wait for confirmation
            const receipt = await tx.wait();
            console.log('✅ Transaction confirmed in block:', receipt.blockNumber);

            return {
                success: true,
                attestationUid: receipt.toString(), // Convert BigInt to string
                txHash: tx.hash // Use transaction hash string instead of full tx object
            };

        } catch (error) {
            console.error('❌ Failed to create EAS identity attestation:', error.message);
            return {
                success: false,
                error: error.message,
                attestationUid: null,
                txHash: null
            };
        }
    }

    async validateIdentity({ body }) {
        try {
            console.log('📥 validateIdentity called with body:', JSON.stringify(body, null, 2));
            
            if (!body) {
                return {
                    valid: false,
                    validatorSignature: '',
                    validator: this.wallet?.address || (() => { throw new Error('CRITICAL: Validator wallet not initialized - check DEPLOY_LOCAL_DEV_VALIDATOR_PRIVATE_KEY or DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY environment variables'); })(),
                    error: 'Request body is required'
                };
            }
            
            const { identifier, proofUrl, registrant, registrantSignature } = body;
            
            console.log(`🔍 Validating identity: ${identifier} → ${registrant}`);

            // Validate required fields
            if (!identifier || !proofUrl || !registrant || !registrantSignature) {
                throw new Error('identifier, proofUrl, registrant, and registrantSignature are required');
            }

            // Use real gist validation
            const gistValidation = await this.validateGistContent(proofUrl, identifier, registrant);
            if (!this.wallet) {
                throw new Error('Validator wallet not initialized - check private key configuration');
            }
            const validator = this.wallet.address;

            if (gistValidation.valid) {
                if (!this.wallet) {
                    throw new Error('Validator wallet not initialized - check private key configuration');
                }
                const validatorPayload = `VALIDATOR_VALIDATION:${identifier}:${registrant}:${proofUrl}`;
                const validatorSignature = await this.wallet.signMessage(validatorPayload);
                return {
                    valid: true,
                    validatorSignature,
                    validator,
                    error: ''
                };
            } else {
                return {
                    valid: false,
                    validatorSignature: '',
                    validator,
                    error: gistValidation.error
                };
            }

        } catch (error) {
            console.error('❌ validateIdentity failed:', error.message);
            throw error;
        }
    }

    async processWebhook({ body }) {
        try {
            const { action, repository, sender, pull_request, issue, review } = body;
            
            console.log('📨 Processing webhook:', action, repository?.full_name);

            // Demonstrate different actor attribution based on event type
            let contributorLogin = sender?.login;
            let eventDescription = `${action} event`;
            
            // Handle different GitHub webhook event types with appropriate actor attribution
            if (pull_request) {
                if (action === 'opened') {
                    contributorLogin = pull_request.user?.login; // PR author gets credit for opening
                    eventDescription = `PR opened by ${contributorLogin}`;
                } else if (action === 'closed' && pull_request.merged) {
                    if (pull_request.merged_by) {
                        // Could create separate contributions for PR author and merger
                        contributorLogin = pull_request.user?.login; // PR author gets credit for merged PR
                        const mergerLogin = pull_request.merged_by?.login;
                        eventDescription = `PR merged: authored by ${contributorLogin}, merged by ${mergerLogin || 'UNKNOWN_MERGER'}`;
                        
                        // In a real implementation, you might create two attestations:
                        // 1. PR author contribution (for getting their PR merged)
                        // 2. Merger contribution (if merger has verified identity, otherwise 0x0)
                    } else {
                        contributorLogin = pull_request.user?.login;
                        eventDescription = `PR merged by ${contributorLogin}`;
                    }
                }
            } else if (issue) {
                if (action === 'opened') {
                    contributorLogin = issue.user?.login; // Issue reporter
                    eventDescription = `Issue opened by ${contributorLogin}`;
                } else if (action === 'closed') {
                    if (issue.closed_by) {
                        contributorLogin = issue.closed_by?.login; // Issue closer gets credit for resolution
                        eventDescription = `Issue closed by ${contributorLogin}`;
                    } else {
                        contributorLogin = issue.user?.login;
                        eventDescription = `Issue closed by ${contributorLogin}`;
                    }
                }
            } else if (review) {
                contributorLogin = review.user?.login; // Reviewer gets credit, not PR author
                eventDescription = `Review ${review.state} by ${contributorLogin}`;
            }

            // Create contribution attestation (real or mock)
            const attestationResult = await this.createContributionAttestation({
                identifier: contributorLogin,
                repository: repository?.full_name,
                action,
                eventUrl: issue?.html_url || pull_request?.html_url || review?.html_url || '',
                eventDescription
            });

            if (attestationResult.success) {
                // Store contribution record with proper actor attribution using schema-compliant field names
                this.contributions.push({
                    attestationUid: attestationResult.attestationUid,
                    action,
                    repository: repository?.full_name,
                    contributor: contributorLogin, // The person who should receive credit
                    sender: sender?.login, // The person who triggered the webhook
                    eventDescription: eventDescription,
                    timestamp: Date.now(),
                    txHash: attestationResult.txHash || null
                });

                console.log(`✅ Attributed contribution: ${eventDescription}`);
                if (attestationResult.txHash) {
                    console.log(`🔗 Transaction hash: ${attestationResult.txHash}`);
                }

                return {
                    processed: true,
                    attestationUid: attestationResult.attestationUid,
                    error: ''
                };
            } else {
                console.error('❌ Failed to create attestation:', attestationResult.error);
                return {
                    processed: false,
                    attestationUid: '',
                    error: attestationResult.error
                };
            }

        } catch (error) {
            console.error('❌ processWebhook failed:', error.message);
            return {
                processed: false,
                attestationUid: '',
                error: error.message
            };
        }
    }

    async lookupGitHubIdentity(identifier) {
        // Check cache first
        if (this.identityCache.has(identifier)) {
            return this.identityCache.get(identifier);
        }

        try {
            // Get the Identity schema UID
            const identitySchemaUID = this.schemaUIDs.Identity;
            if (!identitySchemaUID) {
                throw new Error('Identity schema UID not found in configuration');
            }

            // GraphQL query to get all identity attestations by schema ID
            const query = `
                query GetIdentityAttestations {
                    attestations(
                        where: {
                            schemaId: { equals: "${identitySchemaUID}" }
                        }
                        orderBy: { time: desc }
                    ) {
                        id
                        attester
                        recipient 
                        decodedDataJson
                        time
                    }
                }
            `;

            const response = await fetch(this.EAS_GRAPHQL_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query })
            });

            if (!response.ok) {
                throw new Error(`GraphQL request failed: ${response.statusText}`);
            }

            const { data, errors } = await response.json();
            
            if (errors) {
                throw new Error(`GraphQL errors: ${errors.map(e => e.message).join(', ')}`);
            }

            const attestations = data?.attestations || [];
            console.log(`📋 Found ${attestations.length} identity attestations, scanning for ${identifier}...`);
            
            // Scan through all identity attestations to find the matching GitHub username
            for (const attestation of attestations) {
                try {
                    const decodedData = JSON.parse(attestation.decodedDataJson || '[]');
                    // Find the identifier field in the decoded data array
                    const identifierField = decodedData.find(field => field.name === 'identifier');
                    const ethereumAddressField = decodedData.find(field => field.name === 'ethereumAddress');
                    const identifierValue = identifierField?.value?.value;
                    
                    if (identifierValue === identifier) {
                        const rawAddress = ethereumAddressField?.value?.value || attestation.recipient || attestation.attester;
                        const identity = {
                            attestationUid: attestation.id,
                            ethereumAddress: ethers.getAddress(rawAddress),
                            decodedData: decodedData
                        };
                        
                        console.log(`✅ Found identity attestation for ${identifier}:`);
                        console.log(`   UID: ${identity.attestationUid}`);
                        console.log(`   Address: ${identity.ethereumAddress}`);
                        this.identityCache.set(identifier, identity);
                        return identity;
                    }
                } catch (parseError) {
                    console.warn(`⚠️ Failed to parse attestation ${attestation.id}:`, parseError.message);
                    continue;
                }
            }
            
            // Not found after scanning all attestations
            console.log(`❌ No identity attestation found for identifier: ${identifier} after scanning ${attestations.length} attestations`);
            this.identityCache.set(identifier, null);
            return null;

        } catch (error) {
            console.error(`❌ Failed to lookup identity for ${identifier}:`, error.message);
            this.identityCache.set(identifier, null);
            return null;
        }
    }

    async createContributionAttestation({ identifier, repository, action, eventUrl, eventDescription }) {
        try {
            if (this.mockTransactions) {
                // Mock attestation with proper 64-character UID
                const attestationUid = ethers.hexlify(ethers.randomBytes(32));
                return {
                    success: true,
                    attestationUid,
                    txHash: null
                };
            }

            // Real EAS attestation on Base Sepolia
            if (!this.eas || !this.wallet) {
                throw new Error('EAS not properly initialized');
            }

            // Lookup GitHub identity dynamically - FAIL HARD if not found
            const identity = await this.lookupGitHubIdentity(identifier);
            if (!identity) {
                throw new Error(`No identity attestation found for identifier: ${identifier}. User must register identity first.`);
            }

            // Determine appropriate schema based on event type
            let schemaName = 'IssueContribution'; // Default
            if (eventDescription.includes('PR ') || eventDescription.includes('pull')) {
                schemaName = 'PullRequestContribution';
            } else if (eventDescription.includes('Review') || eventDescription.includes('review')) {
                schemaName = 'ReviewContribution';
            }

            const schemaUID = this.schemaUIDs[schemaName];
            if (!schemaUID) {
                throw new Error(`Schema not found for ${schemaName}`);
            }

            // Get the schema definition from loaded config
            const schemaDefinition = this.schemaDefinitions[schemaName];
            if (!schemaDefinition) {
                throw new Error(`Schema definition not found for ${schemaName}`);
            }

            // Encode contribution data using SchemaEncoder
            const schemaEncoder = new SchemaEncoder(schemaDefinition);
            let encodedData;
            
            if (schemaName === 'IssueContribution') {
                encodedData = schemaEncoder.encodeData([
                    { name: 'domain', value: 'github.com', type: 'string' },
                    { name: 'path', value: repository, type: 'string' },
                    { name: 'contributor', value: identity.ethereumAddress, type: 'address' },
                    { name: 'identityAttestationUid', value: identity.attestationUid, type: 'bytes32' },
                    { name: 'repositoryRegistrationUid', value: '0x0000000000000000000000000000000000000000000000000000000000000000', type: 'bytes32' },
                    { name: 'url', value: eventUrl, type: 'string' },
                    { name: 'eventType', value: action, type: 'string' }
                ]);
            } else if (schemaName === 'PullRequestContribution') {
                encodedData = schemaEncoder.encodeData([
                    { name: 'domain', value: 'github.com', type: 'string' },
                    { name: 'path', value: repository, type: 'string' },
                    { name: 'contributor', value: identity.ethereumAddress, type: 'address' },
                    { name: 'identityAttestationUid', value: identity.attestationUid, type: 'bytes32' },
                    { name: 'repositoryRegistrationUid', value: '0x0000000000000000000000000000000000000000000000000000000000000000', type: 'bytes32' },
                    { name: 'url', value: eventUrl, type: 'string' },
                    { name: 'eventType', value: action, type: 'string' },
                    { name: 'commitHash', value: '0x0000000000000000000000000000000000000000000000000000000000000000', type: 'string' },
                    { name: 'linkedIssueUids', value: [], type: 'bytes32[]' }
                ]);
            } else {
                encodedData = schemaEncoder.encodeData([
                    { name: 'domain', value: 'github.com', type: 'string' },
                    { name: 'path', value: repository, type: 'string' },
                    { name: 'contributor', value: identity.ethereumAddress, type: 'address' },
                    { name: 'identityAttestationUid', value: identity.attestationUid, type: 'bytes32' },
                    { name: 'repositoryRegistrationUid', value: '0x0000000000000000000000000000000000000000000000000000000000000000', type: 'bytes32' },
                    { name: 'url', value: eventUrl, type: 'string' },
                    { name: 'eventType', value: action, type: 'string' },
                    { name: 'reviewedPrUid', value: '0x0000000000000000000000000000000000000000000000000000000000000000', type: 'bytes32' }
                ]);
            }

            console.log('🔗 Creating EAS attestation on Base Sepolia...');
            console.log(`📝 Schema: ${schemaName} (${schemaUID})`);
            console.log('📝 Data:', { identifier, repository, action, eventUrl });
            console.log('👤 Identity:', { ethereumAddress: identity.ethereumAddress, attestationUid: identity.attestationUid });

            // Submit attestation using EAS SDK
            const tx = await this.eas.attest({
                schema: schemaUID,
                data: {
                    recipient: identity.ethereumAddress,
                    expirationTime: 0n,
                    revocable: true,
                    refUID: identity.attestationUid,
                    data: encodedData
                }
            });

            console.log('⏳ Transaction submitted:', tx.txHash);
            
            // Wait for confirmation
            const receipt = await tx.wait();
            console.log('✅ Transaction confirmed in block:', receipt.blockNumber);

            return {
                success: true,
                attestationUid: receipt.toString(), // Convert BigInt to string
                txHash: tx.hash // Use transaction hash string
            };

        } catch (error) {
            console.error('❌ Failed to create EAS attestation:', error.message);
            return {
                success: false,
                error: error.message,
                attestationUid: '',
                txHash: null
            };
        }
    }

    async getContributions({ body }) {
        try {
            const { repository, identity, limit = 50, offset = 0 } = body;
            
            let filteredContributions = [...this.contributions];
            
            if (repository?.path) {
                filteredContributions = filteredContributions.filter(c => 
                    c.repository === repository.path
                );
            }
            
            if (identity?.identifier) {
                filteredContributions = filteredContributions.filter(c => 
                    c.contributor === identity.identifier
                );
            }

            const paginatedContributions = filteredContributions
                .slice(offset, offset + limit);

            return {
                issues: [],
                pullRequests: paginatedContributions,
                reviews: [],
                totalCount: filteredContributions.length
            };

        } catch (error) {
            console.error('❌ getContributions failed:', error.message);
            throw error;
        }
    }

    async getContributionsByIdentity({ body }) {
        return this.getContributions({ body: { identity: body } });
    }

    async getContributionsByRepository({ body }) {
        return this.getContributions({ body: { repository: body } });
    }

    async getContributionsByIdentityUid({ path }) {
        try {
            const { attestationUid } = path;
            
            // Mock lookup by attestation UID
            const contributions = this.contributions.filter(c => 
                c.attestationUid === attestationUid
            );

            return {
                issues: [],
                pullRequests: contributions,
                reviews: [],
                totalCount: contributions.length
            };

        } catch (error) {
            console.error('❌ getContributionsByIdentityUid failed:', error.message);
            throw error;
        }
    }

    async getContributionsByRepositoryUid({ path }) {
        return this.getContributionsByIdentityUid({ path });
    }

    async getLinkedIssues({ path }) {
        try {
            const { prAttestationUid } = path;
            
            return {
                issues: []
            };

        } catch (error) {
            console.error('❌ getLinkedIssues failed:', error.message);
            throw error;
        }
    }

    async getPullRequestReviews({ path }) {
        try {
            const { prAttestationUid } = path;
            
            return {
                reviews: []
            };

        } catch (error) {
            console.error('❌ getPullRequestReviews failed:', error.message);
            throw error;
        }
    }
}

const contributionServiceInstance = new ContributionServiceImpl();

// Wrap each method with Service.successResponse/rejectResponse
const wrapServiceMethod = (methodName) => {
    return (params) => new Promise(async (resolve, reject) => {
        try {
            const result = await contributionServiceInstance[methodName](params);
            resolve(Service.successResponse(result));
        } catch (e) {
            // Return proper validation error for missing required fields
            const statusCode = (e.message && e.message.includes('required')) ? 400 : (e.status || 500);
            reject(Service.rejectResponse(
                { message: e.message || 'Invalid input' },
                statusCode,
            ));
        }
    });
};

// Export all the methods
const registerRepository = wrapServiceMethod('registerRepository');
const getWebhookSecret = wrapServiceMethod('getWebhookSecret');
const listRegisteredRepositories = wrapServiceMethod('listRegisteredRepositories');
const registerIdentity = wrapServiceMethod('registerIdentity');
const validateIdentity = wrapServiceMethod('validateIdentity');
const processWebhook = wrapServiceMethod('processWebhook');
const getContributions = wrapServiceMethod('getContributions');
const getContributionsByIdentity = wrapServiceMethod('getContributionsByIdentity');
const getContributionsByRepository = wrapServiceMethod('getContributionsByRepository');
const getContributionsByIdentityUid = wrapServiceMethod('getContributionsByIdentityUid');
const getContributionsByRepositoryUid = wrapServiceMethod('getContributionsByRepositoryUid');
const getLinkedIssues = wrapServiceMethod('getLinkedIssues');
const getPullRequestReviews = wrapServiceMethod('getPullRequestReviews');

module.exports = {
    registerRepository,
    getWebhookSecret,
    listRegisteredRepositories,
    registerIdentity,
    validateIdentity,
    processWebhook,
    getContributions,
    getContributionsByIdentity,
    getContributionsByRepository,
    getContributionsByIdentityUid,
    getContributionsByRepositoryUid,
    getLinkedIssues,
    getPullRequestReviews,
};