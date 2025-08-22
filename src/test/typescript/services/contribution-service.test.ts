/**
 * Unit tests for ContributionService
 * Tests GitHub business logic and contribution processing with branch-based repository validation
 */

// Mock fetch globally
global.fetch = jest.fn();

// Mock ethers to control keccak256 behavior
jest.mock('ethers', () => ({
  ethers: {
    keccak256: jest.fn(),
    toUtf8Bytes: jest.fn(),
    verifyMessage: jest.fn()
  }
}));

// Mock services to avoid import issues
jest.mock('../../../main/typescript/utils/SchemaConverter.js', () => {
  return jest.fn().mockImplementation(() => ({
    validateJsonData: jest.fn().mockReturnValue({ isValid: true }),
    createAttestationRequest: jest.fn().mockReturnValue({}),
    getSchemaUID: jest.fn().mockReturnValue('0x1234567890abcdef'),
    easGraphqlToJson: jest.fn().mockReturnValue({
      domain: 'github.com',
      identifier: 'testuser'
    })
  }));
});

jest.mock('../../../main/typescript/services/AttestService.js', () => {
  return jest.fn().mockImplementation(() => ({
    CreateAttestation: jest.fn()
  }));
});

jest.mock('../../../main/typescript/services/SignService.js', () => {
  return jest.fn().mockImplementation(() => ({}));
});

// Import after mocking
import ContributionService from '../../../main/typescript/services/ContributionService.js';

describe('ContributionService Tests', () => {
  let contributionService: any;
  let mockCallback: jest.Mock;
  let originalEnv: any;

  beforeEach(() => {
    // Store original environment
    originalEnv = { ...process.env };
    
    mockCallback = jest.fn();
    
    // Reset mocks
    jest.clearAllMocks();
    (global.fetch as jest.Mock).mockClear();
    
    contributionService = new ContributionService();
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('Service Initialization', () => {
    it('should initialize with required services', () => {
      expect(contributionService.converter).toBeDefined();
      expect(contributionService.attestService).toBeDefined();
      expect(contributionService.signService).toBeDefined();
      expect(contributionService.allowedRepositories).toEqual([
        'allenday/eas-attestor-github',
        'ethereum-attestation-service/eas-contracts'
      ]);
    });
  });

  describe('Branch Name Generation', () => {
    it('should generate deterministic branch names from signature', () => {
      const signature = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
      
      const branchName = contributionService.generateBranchName('owner/repo', signature);

      expect(branchName).toBe('repository-registration-abcdef12');
    });

    it('should generate different branch names for different signatures', () => {
      const sig1 = '0xabcdef1234567890000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
      const sig2 = '0x123456789abcdef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

      const branch1 = contributionService.generateBranchName('owner/repo', sig1);
      const branch2 = contributionService.generateBranchName('owner/repo', sig2);

      expect(branch1).toBe('repository-registration-abcdef12');
      expect(branch2).toBe('repository-registration-12345678');
    });

    it('should handle signatures with or without 0x prefix', () => {
      const sigWith0x = '0xabcdef1234567890';
      const sigWithout0x = 'abcdef1234567890';

      const branch1 = contributionService.generateBranchName('owner/repo', sigWith0x);
      const branch2 = contributionService.generateBranchName('owner/repo', sigWithout0x);

      expect(branch1).toBe('repository-registration-abcdef12');
      expect(branch2).toBe('repository-registration-abcdef12');
    });
  });

  describe('GenerateRepositoryBranchName Method', () => {
    it('should generate branch name successfully', async () => {
      const signature = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
      
      const mockCall = {
        request: {
          repository_path: 'owner/repo',
          registrantSignature: signature
        }
      };

      await contributionService.GenerateRepositoryBranchName(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        branch_name: 'repository-registration-abcdef12',
        repository_path: 'owner/repo',
        expected_message: 'github.com/owner/repo',
        generated_at: expect.any(Number)
      });
    });

    it('should handle missing parameters', async () => {
      const mockCall = {
        request: {
          repository_path: 'owner/repo'
          // missing registrantSignature
        }
      };

      await contributionService.GenerateRepositoryBranchName(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Repository path and registrant signature are required'
        }),
        null
      );
    });
  });

  describe('ValidateRepositoryBranch Method', () => {
    it('should validate existing branch successfully', async () => {
      const { ethers } = require('ethers');
      const signature = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
      const registrantAddress = 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'';
      
      // Mock signature verification to return the registrant address
      ethers.verifyMessage.mockReturnValue(registrantAddress);

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          name: 'repository-registration-abcdef12',
          commit: {
            sha: '1234567890abcdef1234567890abcdef12345678'
          }
        })
      });

      const mockCall = {
        request: {
          repository_path: 'owner/repo',
          registrant_address: registrantAddress,
          registrantSignature: signature
        }
      };

      await contributionService.ValidateRepositoryBranch(mockCall, mockCallback);

      expect(ethers.verifyMessage).toHaveBeenCalledWith('github.com/owner/repo', signature);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.github.com/repos/owner/repo/branches/repository-registration-abcdef12',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'EAS-Validator-Service/1.0'
          })
        })
      );

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: true,
        branch_name: 'repository-registration-abcdef12',
        branch_sha: '1234567890abcdef1234567890abcdef12345678',
        verified_at: expect.any(Number),
        error: ''
      });
    });

    it('should handle signature verification failure', async () => {
      const { ethers } = require('ethers');
      const signature = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
      const registrantAddress = 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'';
      const wrongAddress = '0x9999999999999999999999999999999999999999';
      
      // Mock signature verification to return wrong address
      ethers.verifyMessage.mockReturnValue(wrongAddress);

      const mockCall = {
        request: {
          repository_path: 'owner/repo',
          registrant_address: registrantAddress,
          registrantSignature: signature
        }
      };

      await contributionService.ValidateRepositoryBranch(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Signature verification failed - signature does not match registrant address'
        }),
        null
      );
    });

    it('should handle branch not found (404)', async () => {
      const { ethers } = require('ethers');
      const signature = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
      const registrantAddress = 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'';
      
      ethers.verifyMessage.mockReturnValue(registrantAddress);

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 404
      });

      const mockCall = {
        request: {
          repository_path: 'owner/repo',
          registrant_address: registrantAddress,
          registrantSignature: signature
        }
      };

      await contributionService.ValidateRepositoryBranch(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "Branch 'repository-registration-abcdef12' not found. Please create this branch to prove repository write access."
        }),
        null
      );
    });

    it('should handle invalid repository path format', async () => {
      const mockCall = {
        request: {
          repository_path: 'invalid-path',
          registrant_address: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'',
          registrantSignature: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12'
        }
      };

      await contributionService.ValidateRepositoryBranch(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid repository path format - expected owner/repo'
        }),
        null
      );
    });

    it('should handle GitHub API rate limit', async () => {
      const { ethers } = require('ethers');
      const signature = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
      const registrantAddress = 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'';
      
      ethers.verifyMessage.mockReturnValue(registrantAddress);

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 403
      });

      const mockCall = {
        request: {
          repository_path: 'owner/repo',
          registrant_address: registrantAddress,
          registrantSignature: signature
        }
      };

      await contributionService.ValidateRepositoryBranch(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'GitHub API rate limit exceeded - please try again later'
        }),
        null
      );
    });

    it('should handle missing parameters', async () => {
      const mockCall = {
        request: {
          repository_path: 'owner/repo'
          // missing registrant_address and registrantSignature
        }
      };

      await contributionService.ValidateRepositoryBranch(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Repository path, registrant address, and registrant signature are required'
        }),
        null
      );
    });

    it('should handle network errors', async () => {
      const { ethers } = require('ethers');
      const signature = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
      const registrantAddress = 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'';
      
      ethers.verifyMessage.mockReturnValue(registrantAddress);

      (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

      const mockCall = {
        request: {
          repository_path: 'owner/repo',
          registrant_address: registrantAddress,
          registrantSignature: signature
        }
      };

      await contributionService.ValidateRepositoryBranch(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Network error'
        }),
        null
      );
    });
  });

  describe('ValidateGist Method', () => {
    it('should validate gist successfully', async () => {
      const { ethers } = require('ethers');
      ethers.verifyMessage.mockReturnValue('process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'');

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          owner: { login: 'testuser' },
          files: {
            'verification.json': {
              content: JSON.stringify({
                identifier: 'testuser',
                address: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'',
                signature: '0xsignature123',
                message: 'Verify GitHub identity for EAS'
              })
            }
          }
        })
      });

      const mockCall = {
        request: {
          identifier: 'testuser',
          proofUrl: 'https://gist.github.com/testuser/abc123',
          ethereumAddress: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890''
        }
      };

      await contributionService.ValidateGist(mockCall, mockCallback);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.github.com/gists/abc123',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'EAS-Validator-Service/1.0'
          })
        })
      );

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: true,
        gist_id: 'abc123',
        verified_at: expect.any(Number),
        error: ''
      });
    });

    it('should handle gist owner mismatch', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          owner: { login: 'wronguser' },
          files: {}
        })
      });

      const mockCall = {
        request: {
          identifier: 'testuser',
          proofUrl: 'https://gist.github.com/testuser/abc123',
          ethereumAddress: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890''
        }
      };

      await contributionService.ValidateGist(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Gist owner mismatch: expected testuser, found wronguser'
        }),
        null
      );
    });

    it('should handle invalid gist URL', async () => {
      const mockCall = {
        request: {
          identifier: 'testuser',
          proofUrl: 'invalid-url',
          ethereumAddress: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890''
        }
      };

      await contributionService.ValidateGist(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid gist URL format'
        }),
        null
      );
    });

    it('should handle signature verification failure', async () => {
      const { ethers } = require('ethers');
      ethers.verifyMessage.mockReturnValue('0x9999999999999999999999999999999999999999');

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          owner: { login: 'testuser' },
          files: {
            'verification.json': {
              content: JSON.stringify({
                identifier: 'testuser',
                address: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'',
                signature: '0xbadsignature',
                message: 'Verify GitHub identity for EAS'
              })
            }
          }
        })
      });

      const mockCall = {
        request: {
          identifier: 'testuser',
          proofUrl: 'https://gist.github.com/testuser/abc123',
          ethereumAddress: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890''
        }
      };

      await contributionService.ValidateGist(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Signature verification failed - signature does not match Ethereum address'
        }),
        null
      );
    });
  });

  describe('Helper Methods', () => {
    it('should extract gist ID from URL correctly', () => {
      const gistId1 = contributionService.extractGistId('https://gist.github.com/testuser/abc123def456');
      const gistId2 = contributionService.extractGistId('https://gist.github.com/testuser/xyz789');
      
      expect(gistId1).toBe('abc123def456');
      expect(gistId2).toBe('xyz789');
    });

    it('should handle invalid gist URLs', () => {
      const invalidGistId = contributionService.extractGistId('invalid-url');
      expect(invalidGistId).toBeNull();
    });

    it('should identify high-value contributions', () => {
      expect(contributionService.isHighValueContribution('issues', 'closed')).toBe(true);
      expect(contributionService.isHighValueContribution('pull_request', 'merged')).toBe(true);
      expect(contributionService.isHighValueContribution('pull_request_review', 'submitted')).toBe(true);
      
      expect(contributionService.isHighValueContribution('issues', 'opened')).toBe(false);
      expect(contributionService.isHighValueContribution('pull_request', 'opened')).toBe(false);
      expect(contributionService.isHighValueContribution('unknown', 'action')).toBe(undefined);
    });

    it('should convert event types to strings correctly', () => {
      expect(contributionService.getEventTypeString('issues', 'closed')).toBe('ISSUE_EVENT_RESOLVED');
      expect(contributionService.getEventTypeString('issues', 'opened')).toBe('ISSUE_EVENT_OPENED');
      expect(contributionService.getEventTypeString('pull_request', 'merged')).toBe('PR_EVENT_MERGED');
      expect(contributionService.getEventTypeString('pull_request', 'closed')).toBe('PR_EVENT_CLOSED');
      expect(contributionService.getEventTypeString('pull_request_review', 'approved')).toBe('REVIEW_EVENT_APPROVED');
      expect(contributionService.getEventTypeString('unknown', 'action')).toBe('UNKNOWN');
    });
  });

  describe('Error Handling', () => {
    it('should handle service initialization errors gracefully', () => {
      // Test that service can handle mock failures
      expect(() => new ContributionService()).not.toThrow();
    });

    it('should handle fetch network failures', async () => {
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Network failure'));

      const mockCall = {
        request: {
          identifier: 'testuser',
          proofUrl: 'https://gist.github.com/testuser/abc123',
          ethereumAddress: 'process.env.TEST_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890''
        }
      };

      await contributionService.ValidateGist(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Network failure'
        }),
        null
      );
    });
  });
});