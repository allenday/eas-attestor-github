#!/usr/bin/env node

const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Import the service implementation directly
const { registerRepository } = require('../../../src/generated/server/services/ContributionServiceService.js');

// ANSI colors for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

class RepoRegistrationCLI {
    constructor() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        this.network = process.argv.find(arg => arg.startsWith('--network='))?.split('=')[1] || 'base-sepolia';
        this.repoData = {};
    }


    async prompt(question) {
        return new Promise(resolve => {
            this.rl.question(question, resolve);
        });
    }

    async collectRepoData() {
        log('\n📝 Repository Registration Data Collection', 'yellow');
        log('=' .repeat(50), 'yellow');
        
        this.repoData.domain = await this.prompt('🌐 Domain (e.g., github.com): ') || 'github.com';
        this.repoData.path = await this.prompt('📂 Repository path (e.g., owner/repo-name): ');
        
        if (!this.repoData.path) {
            log('❌ Repository path is required', 'red');
            process.exit(1);
        }
        
        this.repoData.url = `https://${this.repoData.domain}/${this.repoData.path}`;
            
        log('\n📋 Repository Data Summary:', 'blue');
        log(`   Domain: ${this.repoData.domain}`, 'cyan');
        log(`   Path: ${this.repoData.path}`, 'cyan');
        log(`   URL: ${this.repoData.url}`, 'cyan');
        
        const confirm = await this.prompt('\n✅ Proceed with registration? (y/N): ');
        if (confirm.toLowerCase() !== 'y') {
            log('❌ Registration cancelled', 'yellow');
            process.exit(0);
        }
    }

    async createVerificationBranch() {
        log('\n🔀 Creating verification branch...', 'yellow');
        
        const branchName = `attestation-verification-${Date.now()}`;
        
        log(`📝 Verification branch: ${branchName}`, 'cyan');
        log('\n⚠️  MANUAL STEP REQUIRED:', 'yellow');
        log('Create a new branch in your repository to prove ownership:', 'white');
        log(`   git checkout -b ${branchName} && git push origin ${branchName}`, 'magenta');
        
        await this.prompt('\n⏳ Press Enter when you have created the verification branch...');
        
        const verificationUrl = `https://api.${this.repoData.domain}/repos/${this.repoData.path}/branches/${branchName}`;
        
        try {
            const response = await fetch(verificationUrl);
            if (!response.ok) {
                throw new Error(`Branch verification failed: ${response.status}`);
            }
            log('✅ Branch verification successful', 'green');
        } catch (error) {
            log(`❌ ${error.message}`, 'red');
            process.exit(1);
        }
        
        this.repoData.proofUrl = `${this.repoData.url}/tree/${branchName}`;
    }

    async createRepositoryAttestation() {
        log('\n📝 Creating repository registration attestation...', 'yellow');
        
        try {
            // Create a simple signature of the repository path + proof URL
            // This proves the user has the ability to create the verification branch
            const messageToSign = `${this.repoData.path}:${this.repoData.proofUrl}`;
            
            // For CLI usage, we'll use a deterministic signature
            // In a real implementation, this would be signed with the registrant's private key
            const registrantSignature = `0x${Buffer.from(messageToSign).toString('hex').padEnd(128, '0')}`;
            
            // Use the service implementation directly
            const registrationData = {
                path: this.repoData.path,
                registrantSignature: registrantSignature,
                registrant: process.env.USER || 'cli-user'
            };
            
            log(`📋 Calling registerRepository service...`, 'cyan');
            log(`📂 Repository: ${registrationData.path}`, 'cyan');
            log(`✏️  Signature (first 20 chars): ${registrantSignature.substring(0, 22)}...`, 'cyan');
            
            const result = await registerRepository({
                body: registrationData
            });
            
            if (result.code === 200) {
                const { attestationUid, webhookSecret } = result.payload;
                
                log(`\n✅ REGISTRATION COMPLETED SUCCESSFULLY!`, 'green');
                log(`🎯 Repository: ${registrationData.path}`, 'green');
                log(`📝 Attestation UID: ${attestationUid}`, 'green');
                log(`🔐 Webhook Secret: ${webhookSecret}`, 'green');
                log(`🔗 Proof URL: ${this.repoData.proofUrl}`, 'green');
                
                log(`\n📋 IMPORTANT - SAVE THESE VALUES:`, 'yellow');
                log(`   Attestation UID: ${attestationUid}`, 'white');
                log(`   Webhook Secret: ${webhookSecret}`, 'white');
                
                return {
                    attestationUID: attestationUid,
                    webhookSecret: webhookSecret,
                    txHash: null
                };
            } else {
                throw new Error(`Registration failed: ${result.message || 'Unknown error'}`);
            }
            
        } catch (error) {
            log(`❌ Failed to create repository attestation: ${error.message}`, 'red');
            throw error;
        }
    }

    async run() {
        try {
            log('🚀 Repository Registration CLI', 'green');
            log('=' .repeat(50), 'green');
            
            await this.collectRepoData();
            await this.createVerificationBranch();
            const result = await this.createRepositoryAttestation();
            
            log('\n🎉 Repository registration completed successfully!', 'green');
            log(`📝 Attestation UID: ${result.attestationUID}`, 'cyan');
            log(`🔐 Webhook Secret: ${result.webhookSecret}`, 'cyan');
            
            if (result.txHash && this.network === 'base-sepolia') {
                log(`🔍 View on Base Sepolia EAS: https://base-sepolia.easscan.org/attestation/view/${result.attestationUID}`, 'blue');
            } else if (result.txHash) {
                log(`🔍 View on Base EAS: https://base.easscan.org/attestation/view/${result.attestationUID}`, 'blue');
            }
            
        } catch (error) {
            log(`❌ Registration failed: ${error.message}`, 'red');
            process.exit(1);
        } finally {
            this.rl.close();
        }
    }
}

// Handle CLI execution
if (require.main === module) {
    const cli = new RepoRegistrationCLI();
    cli.run().catch(console.error);
}

module.exports = RepoRegistrationCLI;