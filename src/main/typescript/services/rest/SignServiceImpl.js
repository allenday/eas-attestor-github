/**
 * SignService REST Implementation - Direct CommonJS version
 * Implementation of the SignService interface for REST endpoints
 */

const Service = require('./Service');
const { ethers } = require('ethers');

class SignServiceImpl {
    constructor() {
        this.wallet = null;
        this.initializeWallet();
    }

    /**
     * Initialize the server's wallet from environment variables
     */
    initializeWallet() {
        try {
            const privateKey = process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY || 
                             process.env.DEPLOY_CLOUD_PROD_VALIDATOR_PRIVATE_KEY ||
                             '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // fallback for testing (hardhat account #0)
            
            this.wallet = new ethers.Wallet(privateKey);
            console.log('🔐 SignService: Initialized with validator address:', this.wallet.address);

        } catch (error) {
            console.error('❌ SignService: Failed to initialize wallet:', error.message);
            throw error;
        }
    }

    /**
     * Get server's public address
     */
    async getServerAddress() {
        try {
            if (!this.wallet) {
                throw new Error('Wallet not initialized');
            }

            console.log('📍 Returning server address:', this.wallet.address);

            return {
                address: this.wallet.address
            };

        } catch (error) {
            console.error('❌ getServerAddress failed:', error.message);
            throw error;
        }
    }

    /**
     * Server signs attestation using validator private key
     */
    async serverSignAttestation(body) {
        try {
            const { schema_type, data, recipient, revocable, expiration_time } = body;
            
            console.log('🔐 Server signing attestation:', {
                schema_type,
                recipient,
                expiration_time,
                revocable
            });

            if (!this.wallet) {
                throw new Error('Wallet not initialized');
            }

            // TODO: Implement actual EAS attestation creation
            const mockAttestationUid = ethers.keccak256(ethers.toUtf8Bytes(
                JSON.stringify({ schema_type, data, recipient, timestamp: Date.now() })
            ));
            const mockTxHash = ethers.keccak256(ethers.toUtf8Bytes(
                `tx-${mockAttestationUid}-${Date.now()}`
            ));

            return {
                attestation_uid: mockAttestationUid,
                transaction_hash: mockTxHash,
                attester: this.wallet.address
            };

        } catch (error) {
            console.error('❌ serverSignAttestation failed:', error.message);
            throw error;
        }
    }

    /**
     * Verify signatures
     */
    async verifySignature(body) {
        try {
            const { message, signature, expected_signer } = body;

            if (!message || !signature) {
                throw new Error('Message and signature are required');
            }

            console.log('🔍 Verifying signature for message:', message.substring(0, 100) + '...');

            let recoveredAddress;
            try {
                recoveredAddress = ethers.verifyMessage(message, signature);
            } catch (verifyError) {
                return {
                    valid: false,
                    signer_address: '0x0000000000000000000000000000000000000000',
                    error: `Invalid signature: ${verifyError.message}`
                };
            }

            let isValid = true;
            let errorMessage = null;

            if (expected_signer) {
                try {
                    isValid = ethers.getAddress(recoveredAddress) === ethers.getAddress(expected_signer);
                    if (!isValid) {
                        errorMessage = `Signature mismatch: expected ${ethers.getAddress(expected_signer)}, got ${ethers.getAddress(recoveredAddress)}`;
                    }
                } catch (error) {
                    isValid = false;
                    errorMessage = `Invalid address format: ${error.message}`;
                }
            }

            return {
                valid: isValid,
                signer_address: recoveredAddress,
                error: errorMessage || ''
            };

        } catch (error) {
            console.error('❌ verifySignature failed:', error.message);
            throw error;
        }
    }
}

const signServiceInstance = new SignServiceImpl();

/**
 * Get server's public address
 */
const getServerAddress = () => new Promise(async (resolve, reject) => {
    try {
        const result = await signServiceInstance.getServerAddress();
        resolve(Service.successResponse(result));
    } catch (e) {
        reject(Service.rejectResponse(
            { message: e.message || 'Invalid input' },
            e.status || 500,
        ));
    }
});

/**
 * Server signs attestation using validator private key
 */
const serverSignAttestation = ({ body }) => new Promise(async (resolve, reject) => {
    try {
        const result = await signServiceInstance.serverSignAttestation(body);
        resolve(Service.successResponse(result));
    } catch (e) {
        reject(Service.rejectResponse(
            { message: e.message || 'Invalid input' },
            e.status || 500,
        ));
    }
});

/**
 * Verify signatures
 */
const verifySignature = ({ body }) => new Promise(async (resolve, reject) => {
    try {
        const result = await signServiceInstance.verifySignature(body);
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

module.exports = {
    getServerAddress,
    serverSignAttestation,
    verifySignature,
};