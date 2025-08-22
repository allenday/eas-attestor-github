/**
 * ContributionService REST Implementation - Direct CommonJS version
 * Implementation of the ContributionService interface for REST endpoints
 */

const Service = require('./Service');

class ContributionServiceImpl {
    constructor() {
        // Mock data storage
        this.repositories = new Map();
        this.identities = new Map();
        this.contributions = [];
        this.webhookSecrets = new Map();
    }

    async registerRepository({ body }) {
        try {
            const { repository_full_name, registrant_signature, registrant } = body;
            
            // Validate required fields
            if (!repository_full_name || !registrant_signature || !registrant) {
                throw new Error('repository_full_name, registrant_signature, and registrant are required');
            }
            
            console.log('📋 Registering repository:', repository_full_name);

            // Generate mock attestation UID
            const attestationUid = `0x${Math.random().toString(16).substr(2, 64)}`;
            
            // Generate webhook secret
            const webhookSecret = `wh_${Math.random().toString(16).substr(2, 32)}`;
            
            // Store repository
            this.repositories.set(repository_full_name, {
                repository_full_name,
                registrant_signature,
                registrant,
                attestation_uid: attestationUid,
                webhook_secret: webhookSecret
            });
            
            this.webhookSecrets.set(repository_full_name, webhookSecret);

            return {
                attestation_uid: attestationUid,
                webhook_secret: webhookSecret
            };

        } catch (error) {
            console.error('❌ registerRepository failed:', error.message);
            throw error;
        }
    }

    async getWebhookSecret({ body }) {
        try {
            const { repository_full_name } = body;
            
            const secret = this.webhookSecrets.get(repository_full_name);
            const registered = this.repositories.has(repository_full_name);

            return {
                webhook_secret: secret || '',
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

    async registerIdentity({ body }) {
        try {
            const { github_username, gist_url, ethereum_address } = body;
            
            console.log('👤 Registering identity:', github_username, '→', ethereum_address);

            // Generate mock validation signature
            const validationSignature = `0x${Math.random().toString(16).substr(2, 128)}`;
            const attestationUid = `0x${Math.random().toString(16).substr(2, 64)}`;
            const validator = "0x742d35Cc6634C0532925a3b8D62F1C9134F7e1be";

            // Store identity
            this.identities.set(github_username, {
                github_username,
                gist_url,
                ethereum_address,
                validation_signature: validationSignature,
                validator,
                attestation_uid: attestationUid
            });

            return {
                attestation_uid: attestationUid,
                validation_signature: validationSignature,
                validator: validator
            };

        } catch (error) {
            console.error('❌ registerIdentity failed:', error.message);
            throw error;
        }
    }

    async validateIdentity({ body }) {
        try {
            const { github_username, gist_url, ethereum_address } = body;
            
            console.log('🔍 Validating identity:', github_username);

            // Mock validation logic
            const isValid = gist_url && gist_url.includes('gist.github.com');
            const validationSignature = isValid ? `0x${Math.random().toString(16).substr(2, 128)}` : '';
            const validator = "0x742d35Cc6634C0532925a3b8D62F1C9134F7e1be";

            return {
                valid: isValid,
                validation_signature: validationSignature,
                validator: validator,
                error: isValid ? '' : 'Invalid gist URL format'
            };

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
                        eventDescription = `PR merged: authored by ${contributorLogin}, merged by ${mergerLogin || '0x0'}`;
                        
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

            // Generate mock contribution attestation
            const attestationUid = `0x${Math.random().toString(16).substr(2, 64)}`;
            
            // Store contribution record with proper actor attribution
            this.contributions.push({
                attestation_uid: attestationUid,
                action,
                repository: repository?.full_name,
                contributor: contributorLogin, // The person who should receive credit
                sender: sender?.login, // The person who triggered the webhook
                event_description: eventDescription,
                timestamp: Date.now()
            });

            console.log(`✅ Attributed contribution: ${eventDescription}`);

            return {
                processed: true,
                attestation_uid: attestationUid,
                error: ''
            };

        } catch (error) {
            console.error('❌ processWebhook failed:', error.message);
            return {
                processed: false,
                attestation_uid: '',
                error: error.message
            };
        }
    }

    async getContributions({ body }) {
        try {
            const { repository, identity, limit = 50, offset = 0 } = body;
            
            let filteredContributions = [...this.contributions];
            
            if (repository?.repository_full_name) {
                filteredContributions = filteredContributions.filter(c => 
                    c.repository === repository.repository_full_name
                );
            }
            
            if (identity?.github_username) {
                filteredContributions = filteredContributions.filter(c => 
                    c.sender === identity.github_username
                );
            }

            const paginatedContributions = filteredContributions
                .slice(offset, offset + limit);

            return {
                issues: [],
                pull_requests: paginatedContributions,
                reviews: [],
                total_count: filteredContributions.length
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
            const { attestation_uid } = path;
            
            // Mock lookup by attestation UID
            const contributions = this.contributions.filter(c => 
                c.attestation_uid === attestation_uid
            );

            return {
                issues: [],
                pull_requests: contributions,
                reviews: [],
                total_count: contributions.length
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
            const { pr_attestation_uid } = path;
            
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
            const { pr_attestation_uid } = path;
            
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