/**
 * Unit tests for AttestService
 * Tests EAS attestation creation and schema operations
 */

// Mock ethers to control blockchain interactions
jest.mock('ethers', () => ({
  ethers: {
    JsonRpcProvider: jest.fn().mockImplementation(() => ({
      getNetwork: jest.fn().mockResolvedValue({ chainId: 84532 })
    })),
    Wallet: jest.fn().mockImplementation(() => ({
      address: process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890',
      connect: jest.fn()
    })),
    Contract: jest.fn().mockImplementation(() => ({
      attest: jest.fn().mockResolvedValue({
        hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        wait: jest.fn().mockResolvedValue({
          hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
          gasUsed: BigInt(100000),
          blockNumber: 12345
        })
      })
    }))
  }
}));

// Mock SchemaConverter
jest.mock('../../../main/typescript/utils/SchemaConverter.js', () => {
  return jest.fn().mockImplementation(() => ({
    getAvailableSchemas: jest.fn().mockReturnValue(['identity', 'repository-registration', 'issue-contribution']),
    getSchemaMetadata: jest.fn().mockImplementation((schemaKey) => {
      const schemas = {
        'identity': {
          uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
          name: 'identity',
          definition: 'string domain,string identifier,address ethereumAddress,string proofUrl,address validator,bytes validationSignature',
          description: 'Domain identity verification'
        },
        'repository-registration': {
          uid: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
          name: 'repository-registration',
          definition: 'string domain,string path,address registrant,bytes registrantSignature,string proofUrl,address validator,bytes validationSignature',
          description: 'Repository registration for contribution monitoring'
        },
        'issue-contribution': {
          uid: '0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba',
          name: 'issue-contribution',
          definition: 'string domain,string path,address contributor,bytes32 identityAttestationUid,bytes32 repositoryRegistrationUid,string url,string eventType',
          description: 'GitHub issue contribution'
        }
      };
      return schemas[schemaKey];
    }),
    findSchemaByUID: jest.fn().mockImplementation((uid) => {
      const uidToKey = {
        '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12': 'identity',
        '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab': 'repository-registration',
        '0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba': 'issue-contribution'
      };
      return uidToKey[uid];
    }),
    jsonToEthereum: jest.fn().mockReturnValue({
      schemaUID: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
      encodedData: '0xabcdef1234567890'
    }),
    createAttestationRequest: jest.fn().mockReturnValue({
      schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
      recipient: '0x742d35Cc6e1B3F2C89c98A4D3bCF8D6D2B6D3D3D',
      expiration_time: 0,
      revocable: true,
      data: '0xabcdef1234567890'
    })
  }));
});

// Import after mocking
import AttestService from '../../../main/typescript/services/AttestService.js';

describe('AttestService Tests', () => {
  let attestService: any;
  let mockCallback: jest.Mock;
  let originalEnv: any;

  beforeEach(() => {
    // Store original environment
    originalEnv = { ...process.env };
    
    // Set up test environment variables
    process.env.NODE_ENV = 'test';
    process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
    
    mockCallback = jest.fn();
    
    // Reset mocks
    jest.clearAllMocks();
    
    attestService = new AttestService();
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('Service Initialization', () => {
    it('should initialize with SchemaConverter', () => {
      expect(attestService.converter).toBeDefined();
    });
  });

  describe('CreateAttestation Method', () => {
    it('should create attestation successfully', async () => {
      const { ethers } = require('ethers');
      
      const mockCall = {
        request: {
          schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
          recipient: process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890',
          expiration_time: 0,
          revocable: true,
          data: '0xabcdef1234567890'
        }
      };

      await attestService.CreateAttestation(mockCall, mockCallback);

      // Verify provider was created with correct RPC URL (staging for test env)
      expect(ethers.JsonRpcProvider).toHaveBeenCalledWith('https://sepolia.base.org');

      // Verify wallet was created with private key and provider
      expect(ethers.Wallet).toHaveBeenCalledWith(
        '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        expect.any(Object)
      );

      // Verify contract was created with correct parameters
      expect(ethers.Contract).toHaveBeenCalledWith(
        '0x4200000000000000000000000000000000000021',
        expect.arrayContaining([expect.stringContaining('function attest')]),
        expect.any(Object)
      );

      // Verify successful callback
      expect(mockCallback).toHaveBeenCalledWith(null, {
        success: true,
        attestation_uid: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        transaction_hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        gas_used: '100000',
        block_number: 12345
      });
    });

    it('should use production RPC URL in production environment', async () => {
      const { ethers } = require('ethers');
      
      // Temporarily set production environment
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const mockCall = {
        request: {
          schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
          recipient: process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890',
          data: '0xabcdef1234567890'
        }
      };

      await attestService.CreateAttestation(mockCall, mockCallback);

      // Verify production RPC URL was used
      expect(ethers.JsonRpcProvider).toHaveBeenCalledWith('https://mainnet.base.org');
      
      // Restore original environment
      process.env.NODE_ENV = originalNodeEnv;
    });

    it('should handle missing private key', async () => {
      delete process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY;
      delete process.env.DEPLOY_CLOUD_PROD_VALIDATOR_PRIVATE_KEY;

      const mockCall = {
        request: {
          schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
          data: '0xabcdef1234567890'
        }
      };

      await attestService.CreateAttestation(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Validator private key not configured'
        }),
        null
      );
    });

    it('should use default values for optional parameters', async () => {
      const { ethers } = require('ethers');
      
      const mockCall = {
        request: {
          schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
          data: '0xabcdef1234567890'
          // No recipient, expiration_time, or revocable
        }
      };

      const mockContract = {
        attest: jest.fn().mockResolvedValue({
          hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
          wait: jest.fn().mockResolvedValue({
            hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
            gasUsed: BigInt(100000),
            blockNumber: 12345
          })
        })
      };

      ethers.Contract.mockImplementation(() => mockContract);

      await attestService.CreateAttestation(mockCall, mockCallback);

      // Verify attest was called with default values
      expect(mockContract.attest).toHaveBeenCalledWith({
        schema: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        data: {
          recipient: process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890', // wallet address
          expirationTime: 0,
          revocable: true,
          refUID: '0x0000000000000000000000000000000000000000000000000000000000000000',
          data: '0xabcdef1234567890',
          value: 0
        }
      });
    });

    it('should handle blockchain transaction failure', async () => {
      const { ethers } = require('ethers');
      
      const mockContract = {
        attest: jest.fn().mockRejectedValue(new Error('Transaction failed'))
      };

      ethers.Contract.mockImplementation(() => mockContract);

      const mockCall = {
        request: {
          schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
          data: '0xabcdef1234567890'
        }
      };

      await attestService.CreateAttestation(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Transaction failed'
        }),
        null
      );
    });

    it('should handle transaction receipt failure', async () => {
      const { ethers } = require('ethers');
      
      const mockContract = {
        attest: jest.fn().mockResolvedValue({
          hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
          wait: jest.fn().mockRejectedValue(new Error('Receipt timeout'))
        })
      };

      ethers.Contract.mockImplementation(() => mockContract);

      const mockCall = {
        request: {
          schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
          data: '0xabcdef1234567890'
        }
      };

      await attestService.CreateAttestation(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Receipt timeout'
        }),
        null
      );
    });
  });

  describe('GetSchemas Method', () => {
    it('should return all available schemas', async () => {
      const mockCall = { request: {} };

      await attestService.GetSchemas(mockCall, mockCallback);

      expect(attestService.converter.getAvailableSchemas).toHaveBeenCalled();
      expect(attestService.converter.getSchemaMetadata).toHaveBeenCalledTimes(3);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        schemas: [
          {
            schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
            name: 'identity',
            definition: 'string domain,string identifier,address ethereumAddress,string proofUrl,address validator,bytes validationSignature',
            description: 'GitHub identity attestation'
          },
          {
            schema_uid: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
            name: 'repository-registration',
            definition: 'string domain,string path,address registrant,bytes registrantSignature,string proofUrl,address validator,bytes validationSignature',
            description: 'Repository registration for contribution monitoring'
          },
          {
            schema_uid: '0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba',
            name: 'issue-contribution',
            definition: 'string domain,string path,address contributor,bytes32 identityAttestationUid,bytes32 repositoryRegistrationUid,string url,string eventType',
            description: 'GitHub issue contribution'
          }
        ]
      });
    });

    it('should handle converter errors', async () => {
      attestService.converter.getAvailableSchemas.mockImplementation(() => {
        throw new Error('Schema loading failed');
      });

      const mockCall = { request: {} };

      await attestService.GetSchemas(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Schema loading failed'
        }),
        null
      );
    });
  });

  describe('GetSchema Method', () => {
    it('should return specific schema by UID', async () => {
      const mockCall = {
        request: {
          schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12'
        }
      };

      await attestService.GetSchema(mockCall, mockCallback);

      expect(attestService.converter.findSchemaByUID).toHaveBeenCalledWith(
        '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12'
      );
      expect(attestService.converter.getSchemaMetadata).toHaveBeenCalledWith('identity');

      expect(mockCallback).toHaveBeenCalledWith(null, {
        schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        name: 'identity',
        definition: 'string domain,string identifier,address ethereumAddress,string proofUrl,address validator,bytes validationSignature',
        description: 'GitHub identity attestation'
      });
    });

    it('should handle unknown schema UID', async () => {
      attestService.converter.findSchemaByUID.mockImplementation(() => {
        throw new Error('Schema not found');
      });

      const mockCall = {
        request: {
          schema_uid: '0xunknown1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        }
      };

      await attestService.GetSchema(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Schema not found'
        }),
        null
      );
    });

    it('should handle missing schema UID parameter', async () => {
      const mockCall = {
        request: {}
      };

      await attestService.GetSchema(mockCall, mockCallback);

      expect(attestService.converter.findSchemaByUID).toHaveBeenCalledWith(undefined);
    });
  });

  describe('Helper Methods', () => {
    it('should encode schema data correctly', () => {
      const schemaKey = 'identity';
      const data = {
        domain: 'github.com',
        identifier: 'testuser',
        ethereumAddress: process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890'
      };

      const result = attestService.encodeSchemaData(schemaKey, data);

      expect(attestService.converter.jsonToEthereum).toHaveBeenCalledWith(schemaKey, data);
      expect(result).toEqual({
        schemaUID: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        encodedData: '0xabcdef1234567890'
      });
    });

    it('should create attestation request correctly', () => {
      const schemaKey = 'identity';
      const data = {
        domain: 'github.com',
        identifier: 'testuser'
      };
      const recipient = process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890';
      const options = { revocable: false };

      const result = attestService.createAttestationRequest(schemaKey, data, recipient, options);

      expect(attestService.converter.createAttestationRequest).toHaveBeenCalledWith(
        schemaKey,
        data,
        recipient,
        options
      );
      expect(result).toEqual({
        schema_uid: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        recipient: process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_ADDRESS || '0x1234567890123456789012345678901234567890',
        expiration_time: 0,
        revocable: true,
        data: '0xabcdef1234567890'
      });
    });

    it('should handle null recipient in createAttestationRequest', () => {
      const schemaKey = 'identity';
      const data = { domain: 'github.com' };

      const result = attestService.createAttestationRequest(schemaKey, data);

      expect(attestService.converter.createAttestationRequest).toHaveBeenCalledWith(
        schemaKey,
        data,
        null,
        {}
      );
    });
  });

  describe('Error Handling', () => {
    it('should handle service initialization errors gracefully', () => {
      // Test that service can handle mock failures
      expect(() => new AttestService()).not.toThrow();
    });

    it('should handle converter initialization failures', () => {
      // Create a temporary mock that throws
      jest.doMock('../../../main/typescript/utils/SchemaConverter.js', () => {
        return jest.fn().mockImplementation(() => {
          throw new Error('Converter init failed');
        });
      });
      
      // Clear module cache and re-require
      jest.resetModules();
      const AttestServiceWithFailingConverter = require('../../../main/typescript/services/AttestService.js').default;
      
      expect(() => new AttestServiceWithFailingConverter()).toThrow('Converter init failed');
      
      // Restore the original mock
      jest.resetModules();
    });
  });

  describe('Environment Configuration', () => {
    it('should handle different environment configurations', () => {
      // Test that the service can be initialized with different environment variables
      expect(() => {
        process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY = '0xstaging123';
        new AttestService();
      }).not.toThrow();
      
      expect(() => {
        delete process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY;
        process.env.DEPLOY_CLOUD_PROD_VALIDATOR_PRIVATE_KEY = '0xprod456';
        new AttestService();
      }).not.toThrow();
    });
  });
});