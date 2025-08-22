#!/usr/bin/env node

const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { ethers } = require('ethers');

// Import the service implementation directly
const { registerIdentity } = require('../../../src/generated/server/services/ContributionServiceService.js');

// ANSI colors for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    reset: '\x1b[0m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

class IdentityRegistrationCLI {
    constructor() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        this.network = process.argv.find(arg => arg.startsWith('--network='))?.split('=')[1] || 'base-sepolia';
        this.identityData = {};
    }

    async prompt(question) {
        return new Promise(resolve => {
            this.rl.question(question, resolve);
        });
    }

    async collectIdentityData() {
        log('\n📝 Identity Registration Data Collection', 'yellow');
        log('=' .repeat(50), 'yellow');
        
        this.identityData.githubUsername = await this.prompt('👤 GitHub username: ');
        this.identityData.registrant = await this.prompt('🔗 Ethereum address (0x...): ');
        this.identityData.privateKey = await this.prompt('🔐 Private key for signing (0x...): ');
        
        if (!this.identityData.githubUsername) {
            log('❌ GitHub username is required', 'red');
            process.exit(1);
        }
        
        if (!this.identityData.registrant || !this.identityData.registrant.startsWith('0x')) {
            log('❌ Valid Ethereum address (starting with 0x) is required', 'red');
            process.exit(1);
        }
        
        if (!this.identityData.privateKey || !this.identityData.privateKey.startsWith('0x')) {
            log('❌ Valid private key (starting with 0x) is required', 'red');
            process.exit(1);
        }
        
        // Validate that the private key corresponds to the registrant address
        try {
            const wallet = new ethers.Wallet(this.identityData.privateKey);
            if (wallet.address.toLowerCase() !== this.identityData.registrant.toLowerCase()) {
                log(`❌ Private key does not match registrant address`, 'red');
                log(`   Expected: ${this.identityData.registrant}`, 'red');
                log(`   Derived: ${wallet.address}`, 'red');
                process.exit(1);
            }
            
            // Use the properly checksummed address from the wallet
            this.identityData.registrant = wallet.address;
            log(`✅ Private key matches registrant address: ${this.identityData.registrant}`, 'green');
        } catch (error) {
            log(`❌ Invalid private key: ${error.message}`, 'red');
            process.exit(1);
        }
            
        log('\n📋 Identity Data Summary:', 'blue');
        log(`   GitHub Username: ${this.identityData.githubUsername}`, 'cyan');
        log(`   Ethereum Address: ${this.identityData.registrant}`, 'cyan');
        
        const confirm = await this.prompt('\n✅ Proceed with identity registration? (y/N): ');
        if (confirm.toLowerCase() !== 'y') {
            log('❌ Identity registration cancelled', 'yellow');
            process.exit(0);
        }
    }

    async createVerificationGist() {
        log('\n📝 Creating verification gist...', 'yellow');
        
        // First create the base message to sign (without the gist URL since we don't have it yet)
        const baseMessage = `github.com${this.identityData.githubUsername}${this.identityData.registrant}`;
        
        // Sign the base message with the registrant's private key
        const wallet = new ethers.Wallet(this.identityData.privateKey);
        const registrantSignature = await wallet.signMessage(baseMessage);
        
        const verificationContent = {
            domain: "github.com",
            identifier: this.identityData.githubUsername,
            registrant: wallet.address, // Use wallet's properly checksummed address
            registrantSignature: registrantSignature
        };
        
        const gistDescription = `EAS Identity Verification for ${this.identityData.githubUsername}`;
        const fileName = 'eas-identity-verification.json';
        
        log(`📝 Copy this JSON content for your gist:`, 'cyan');
        log('─'.repeat(50), 'cyan');
        console.log(JSON.stringify(verificationContent, null, 2));
        log('─'.repeat(50), 'cyan');
        
        log('\n⚠️  MANUAL STEP REQUIRED:', 'yellow');
        log('Create a public gist with this content:', 'white');
        log('1. Go to https://gist.github.com', 'white');
        log('2. Create a new public gist:', 'white');
        log(`   - Description: ${gistDescription}`, 'magenta');
        log(`   - Filename: ${fileName}`, 'magenta');
        log(`   - Content: Copy the JSON above (between the lines)`, 'magenta');
        log('3. Make sure it\'s PUBLIC (not secret)', 'white');
        log('4. Copy the gist URL (e.g., https://gist.github.com/username/abc123)', 'white');
        
        const gistUrl = await this.prompt('\n🔗 Paste the gist URL here: ');
        
        if (!gistUrl || !gistUrl.includes('gist.github.com')) {
            log('❌ Invalid gist URL. Must be a GitHub gist URL.', 'red');
            process.exit(1);
        }
        
        // Verify the gist exists and is accessible
        try {
            const response = await fetch(gistUrl);
            if (!response.ok) {
                let errorMessage = `Gist verification failed: ${response.status} ${response.statusText}`;
                
                // Try to get more details from response headers or body
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    try {
                        const errorData = await response.json();
                        if (errorData.message) {
                            errorMessage += `\n   GitHub API Error: ${errorData.message}`;
                        }
                    } catch (parseError) {
                        // Ignore JSON parse errors
                    }
                } else if (contentType && contentType.includes('text/')) {
                    try {
                        const errorText = await response.text();
                        if (errorText && errorText.length < 200) {
                            errorMessage += `\n   Response: ${errorText}`;
                        }
                    } catch (textError) {
                        // Ignore text parse errors
                    }
                }
                
                // Check for rate limiting
                if (response.status === 403) {
                    const rateLimitRemaining = response.headers.get('x-ratelimit-remaining');
                    const rateLimitReset = response.headers.get('x-ratelimit-reset');
                    if (rateLimitRemaining === '0' && rateLimitReset) {
                        const resetTime = new Date(parseInt(rateLimitReset) * 1000);
                        errorMessage += `\n   Rate limit exceeded. Try again after ${resetTime.toLocaleTimeString()}`;
                    }
                }
                
                throw new Error(errorMessage);
            }
            log('✅ Gist verification successful', 'green');
        } catch (error) {
            log(`❌ ${error.message}`, 'red');
            process.exit(1);
        }
        
        this.identityData.gistUrl = gistUrl;
    }

    async createIdentityAttestation() {
        log('\n📝 Creating identity attestation...', 'yellow');
        
        try {
            // Create cryptographic signature of the identity data
            // This proves the user controls both the GitHub account and has the Ethereum private key
            const wallet = new ethers.Wallet(this.identityData.privateKey);
            const messageToSign = `github.com${this.identityData.githubUsername}${wallet.address}${this.identityData.gistUrl}`;
            
            // Sign the message with the registrant's private key
            const registrantSignature = await wallet.signMessage(messageToSign);
            
            log(`🔐 Message signed: ${messageToSign}`, 'cyan');
            log(`✏️  Signature: ${registrantSignature}`, 'cyan');
            
            // Use the service implementation directly with new field names
            const identityRegistrationData = {
                identifier: this.identityData.githubUsername,
                registrant: wallet.address, // Use wallet's properly checksummed address
                proofUrl: this.identityData.gistUrl,
                registrantSignature: registrantSignature
            };
            
            log(`📋 Calling registerIdentity service...`, 'cyan');
            log(`👤 GitHub Username: ${identityRegistrationData.identifier}`, 'cyan');
            log(`🔗 Ethereum Address: ${identityRegistrationData.registrant}`, 'cyan');
            log(`📝 Gist URL: ${identityRegistrationData.proofUrl}`, 'cyan');
            
            const result = await registerIdentity({
                body: identityRegistrationData
            });
            
            if (result.code === 200) {
                const { attestationUid, validatorSignature, validator } = result.payload;
                
                log(`\n✅ IDENTITY REGISTRATION COMPLETED SUCCESSFULLY!`, 'green');
                log(`👤 GitHub Username: ${identityRegistrationData.identifier}`, 'green');
                log(`🔗 Ethereum Address: ${identityRegistrationData.registrant}`, 'green');
                log(`📝 Identity Attestation UID: ${attestationUid}`, 'green');
                log(`✏️  Validator Signature: ${validatorSignature}`, 'green');
                log(`🔐 Validator Address: ${validator}`, 'green');
                log(`🔗 Gist Proof: ${identityRegistrationData.proofUrl}`, 'green');
                                
                return {
                    attestationUID: attestationUid,
                    validatorSignature: validatorSignature,
                    validator: validator,
                    txHash: null
                };
            } else {
                let errorMessage = `Identity registration failed (HTTP ${result.code || 'unknown'})`;
                if (result.message) {
                    errorMessage += `\n   Service Error: ${result.message}`;
                }
                if (result.payload && result.payload.message) {
                    errorMessage += `\n   Details: ${result.payload.message}`;
                }
                if (result.error && typeof result.error === 'object') {
                    errorMessage += `\n   Error Object: ${JSON.stringify(result.error, null, 2)}`;
                } else if (result.error) {
                    errorMessage += `\n   Error: ${result.error}`;
                }
                throw new Error(errorMessage);
            }
            
        } catch (error) {
            // Enhanced error display for service failures
            let errorMessage = `Failed to create identity attestation: ${error.message}`;
            
            // Check if this is an HTTP-related error with more details
            if (error.code) {
                errorMessage += `\n   HTTP Status: ${error.code}`;
            }
            if (error.response) {
                errorMessage += `\n   Response: ${JSON.stringify(error.response, null, 2)}`;
            }
            
            log(`❌ ${errorMessage}`, 'red');
            throw error;
        }
    }

    async run() {
        try {
            log('🚀 Identity Registration CLI', 'green');
            log('=' .repeat(50), 'green');
            
            await this.collectIdentityData();
            await this.createVerificationGist();
            const result = await this.createIdentityAttestation();
            
            log('\n🎉 Identity registration completed successfully!', 'green');
            
            if (result.txHash && this.network === 'base-sepolia') {
                log(`🔍 View on Base Sepolia EAS: https://base-sepolia.easscan.org/attestation/view/${result.attestationUID}`, 'blue');
            } else if (result.txHash) {
                log(`🔍 View on Base EAS: https://base.easscan.org/attestation/view/${result.attestationUID}`, 'blue');
            }
            
        } catch (error) {
            log(`❌ Identity registration failed: ${error.message}`, 'red');
            process.exit(1);
        } finally {
            this.rl.close();
        }
    }
}

// Handle CLI execution
if (require.main === module) {
    const cli = new IdentityRegistrationCLI();
    cli.run().catch(console.error);
}

module.exports = IdentityRegistrationCLI;