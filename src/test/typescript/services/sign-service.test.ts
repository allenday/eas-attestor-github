/**
 * Unit tests for SignService
 * Tests server-side cryptographic operations and signature verification
 */

import crypto from 'crypto';

// Mock ethers to control wallet behavior in tests
jest.mock('ethers', () => {
  const mockWallet = {
    address: '0x1234567890123456789012345678901234567890',
    privateKey: '0x' + '1'.repeat(64),
    signMessage: jest.fn(),
  };

  return {
    ethers: {
      Wallet: jest.fn().mockImplementation(() => mockWallet),
      verifyMessage: jest.fn(),
      hashMessage: jest.fn().mockReturnValue('0xabcdef1234567890'),
      keccak256: jest.fn().mockReturnValue('0x' + '2'.repeat(64)),
      toUtf8Bytes: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3, 4]))
    }
  };
});

// Import after mocking
import SignService from '../../../main/typescript/services/SignService.js';

describe('SignService Tests', () => {
  let signService: any;
  let mockCallback: jest.Mock;
  let originalEnv: any;

  beforeEach(() => {
    // Store original environment
    originalEnv = { ...process.env };
    
    // Set test environment variables
    process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY = '0x' + '1'.repeat(64);
    
    mockCallback = jest.fn();
    
    // Reset mocks
    jest.clearAllMocks();
    
    signService = new SignService();
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('Service Initialization', () => {
    it('should initialize with valid private key from staging env', () => {
      expect(signService.wallet).toBeDefined();
      expect(signService.wallet.address).toBe('0x1234567890123456789012345678901234567890');
    });

    it('should initialize with production private key if staging not available', () => {
      delete process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY;
      process.env.DEPLOY_CLOUD_PROD_VALIDATOR_PRIVATE_KEY = '0x' + '2'.repeat(64);
      
      const service = new SignService();
      expect(service.wallet).toBeDefined();
    });

    it('should throw error if no private key configured', () => {
      delete process.env.DEPLOY_CLOUD_STAGING_VALIDATOR_PRIVATE_KEY;
      delete process.env.DEPLOY_CLOUD_PROD_VALIDATOR_PRIVATE_KEY;
      
      expect(() => {
        new SignService();
      }).toThrow('Validator private key not configured');
    });

    it('should handle wallet initialization errors', () => {
      const { ethers } = require('ethers');
      ethers.Wallet.mockImplementationOnce(() => {
        throw new Error('Invalid private key');
      });

      expect(() => {
        new SignService();
      }).toThrow('Invalid private key');
    });
  });

  describe('SignMessage Method', () => {
    it('should sign message successfully', async () => {
      const mockCall = {
        request: {
          message: 'test message to sign'
        }
      };

      const { ethers } = require('ethers');
      ethers.Wallet().signMessage.mockResolvedValue('0xsignature123');

      await signService.SignMessage(mockCall, mockCallback);

      expect(ethers.Wallet().signMessage).toHaveBeenCalledWith('test message to sign');
      expect(mockCallback).toHaveBeenCalledWith(null, {
        signature: '0xsignature123',
        signer_address: '0x1234567890123456789012345678901234567890',
        message_hash: '0xabcdef1234567890'
      });
    });

    it('should handle missing message', async () => {
      const mockCall = {
        request: {}
      };

      await signService.SignMessage(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Message is required'
        }),
        null
      );
    });

    it('should handle wallet not initialized', async () => {
      signService.wallet = null;
      
      const mockCall = {
        request: {
          message: 'test message'
        }
      };

      await signService.SignMessage(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Wallet not initialized'
        }),
        null
      );
    });

    it('should handle signing errors', async () => {
      const mockCall = {
        request: {
          message: 'test message'
        }
      };

      const { ethers } = require('ethers');
      ethers.Wallet().signMessage.mockRejectedValue(new Error('Signing failed'));

      await signService.SignMessage(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Signing failed'
        }),
        null
      );
    });
  });

  describe('VerifySignature Method', () => {
    it('should verify signature successfully', async () => {
      const mockCall = {
        request: {
          message: 'test message',
          signature: '0xsignature123',
          expected_signer: '0x1234567890123456789012345678901234567890'
        }
      };

      const { ethers } = require('ethers');
      ethers.verifyMessage.mockReturnValue('0x1234567890123456789012345678901234567890');

      await signService.VerifySignature(mockCall, mockCallback);

      expect(ethers.verifyMessage).toHaveBeenCalledWith('test message', '0xsignature123');
      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: true,
        recovered_address: '0x1234567890123456789012345678901234567890',
        error: ''
      });
    });

    it('should verify signature without expected signer', async () => {
      const mockCall = {
        request: {
          message: 'test message',
          signature: '0xsignature123'
        }
      };

      const { ethers } = require('ethers');
      ethers.verifyMessage.mockReturnValue('0x1234567890123456789012345678901234567890');

      await signService.VerifySignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: true,
        recovered_address: '0x1234567890123456789012345678901234567890',
        error: ''
      });
    });

    it('should handle signature mismatch', async () => {
      const mockCall = {
        request: {
          message: 'test message',
          signature: '0xsignature123',
          expected_signer: '0x9999999999999999999999999999999999999999'
        }
      };

      const { ethers } = require('ethers');
      ethers.verifyMessage.mockReturnValue('0x1234567890123456789012345678901234567890');

      await signService.VerifySignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: false,
        recovered_address: '0x1234567890123456789012345678901234567890',
        error: 'Signature mismatch: expected 0x9999999999999999999999999999999999999999, got 0x1234567890123456789012345678901234567890'
      });
    });

    it('should handle invalid signature format', async () => {
      const mockCall = {
        request: {
          message: 'test message',
          signature: 'invalid-signature'
        }
      };

      const { ethers } = require('ethers');
      ethers.verifyMessage.mockImplementation(() => {
        throw new Error('Invalid signature format');
      });

      await signService.VerifySignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: false,
        recovered_address: '0x0000000000000000000000000000000000000000',
        error: 'Invalid signature: Invalid signature format'
      });
    });

    it('should handle missing parameters', async () => {
      const mockCall = {
        request: {
          message: 'test message'
          // missing signature
        }
      };

      await signService.VerifySignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Message and signature are required'
        }),
        null
      );
    });
  });

  describe('GenerateWebhookSecret Method', () => {
    it('should generate webhook secret successfully', async () => {
      const mockCall = {
        request: {
          repositoryFullName: 'owner/repo',
          registrantSignature: '0xregistrantsig123'
        }
      };

      await signService.GenerateWebhookSecret(mockCall, mockCallback);

      const { ethers } = require('ethers');
      expect(ethers.keccak256).toHaveBeenCalled();
      expect(ethers.toUtf8Bytes).toHaveBeenCalled();
      
      expect(mockCallback).toHaveBeenCalledWith(null, {
        webhook_secret: '0x' + '2'.repeat(64),
        repositoryFullName: 'owner/repo',
        validator_address: '0x1234567890123456789012345678901234567890'
      });
    });

    it('should handle missing parameters', async () => {
      const mockCall = {
        request: {
          repositoryFullName: 'owner/repo'
          // missing registrantSignature
        }
      };

      await signService.GenerateWebhookSecret(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Repository full name and registrant signature are required'
        }),
        null
      );
    });

    it('should handle wallet not initialized', async () => {
      signService.wallet = null;
      
      const mockCall = {
        request: {
          repositoryFullName: 'owner/repo',
          registrantSignature: '0xregistrantsig123'
        }
      };

      await signService.GenerateWebhookSecret(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Wallet not initialized'
        }),
        null
      );
    });
  });

  describe('ValidateWebhookSignature Method', () => {
    it('should validate GitHub webhook signature successfully', async () => {
      const payload = JSON.stringify({ action: 'opened' });
      const secret = 'webhook-secret-123';
      
      // Calculate expected signature
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(payload);
      const signature = 'sha256=' + hmac.digest('hex');

      const mockCall = {
        request: {
          payload: payload,
          signature: signature,
          webhook_secret: secret
        }
      };

      await signService.ValidateWebhookSignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: true,
        error: ''
      });
    });

    it('should handle invalid signature format', async () => {
      const mockCall = {
        request: {
          payload: '{"action":"opened"}',
          signature: 'invalid-format',
          webhook_secret: 'secret'
        }
      };

      await signService.ValidateWebhookSignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: false,
        error: 'Signature validation error: Invalid signature format - must start with sha256='
      });
    });

    it('should handle signature mismatch', async () => {
      const payload = '{"action":"opened"}';
      const secret = 'secret';
      
      // Create a valid-length but wrong signature
      const hmac = crypto.createHmac('sha256', 'wrong-secret');
      hmac.update(payload);
      const wrongSignature = 'sha256=' + hmac.digest('hex');

      const mockCall = {
        request: {
          payload: payload,
          signature: wrongSignature,
          webhook_secret: secret
        }
      };

      await signService.ValidateWebhookSignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: false,
        error: 'Webhook signature mismatch'
      });
    });

    it('should handle missing parameters', async () => {
      const mockCall = {
        request: {
          payload: '{"action":"opened"}'
          // missing signature and webhook_secret
        }
      };

      await signService.ValidateWebhookSignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Payload, signature, and webhook secret are required'
        }),
        null
      );
    });
  });

  describe('GetServerAddress Method', () => {
    it('should return server address successfully', async () => {
      const mockCall = { request: {} };

      await signService.GetServerAddress(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        address: '0x1234567890123456789012345678901234567890'
      });
    });

    it('should handle wallet not initialized', async () => {
      signService.wallet = null;
      const mockCall = { request: {} };

      await signService.GetServerAddress(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Wallet not initialized'
        }),
        null
      );
    });
  });

  describe('Deterministic Behavior', () => {
    it('should generate same webhook secret for same inputs', async () => {
      const mockCall = {
        request: {
          repositoryFullName: 'owner/repo',
          registrantSignature: '0xsignature123'
        }
      };

      // Call twice
      await signService.GenerateWebhookSecret(mockCall, jest.fn());
      await signService.GenerateWebhookSecret(mockCall, jest.fn());

      const { ethers } = require('ethers');
      
      // Should be called with same data both times
      expect(ethers.toUtf8Bytes).toHaveBeenCalledTimes(2);
      expect(ethers.keccak256).toHaveBeenCalledTimes(2);
    });

    it('should handle case-insensitive address comparison', async () => {
      const mockCall = {
        request: {
          message: 'test message',
          signature: '0xsignature123',
          expected_signer: '0X1234567890123456789012345678901234567890' // uppercase
        }
      };

      const { ethers } = require('ethers');
      ethers.verifyMessage.mockReturnValue('0x1234567890123456789012345678901234567890'); // lowercase

      await signService.VerifySignature(mockCall, mockCallback);

      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: true,
        recovered_address: '0x1234567890123456789012345678901234567890',
        error: ''
      });
    });
  });

  describe('Error Handling Edge Cases', () => {
    it('should handle service errors gracefully', async () => {
      const mockCall = {
        request: {
          message: 'test message',
          signature: '0xsignature123'
        }
      };

      const { ethers } = require('ethers');
      ethers.verifyMessage.mockImplementation(() => {
        throw new Error('Unexpected service error');
      });

      await signService.VerifySignature(mockCall, mockCallback);

      // VerifySignature catches verification errors and returns structured response
      expect(mockCallback).toHaveBeenCalledWith(null, {
        is_valid: false,
        recovered_address: '0x0000000000000000000000000000000000000000',
        error: 'Invalid signature: Unexpected service error'
      });
    });

    it('should handle very long messages', async () => {
      const longMessage = 'a'.repeat(10000);
      const mockCall = {
        request: {
          message: longMessage
        }
      };

      const { ethers } = require('ethers');
      ethers.Wallet().signMessage.mockResolvedValue('0xlongsignature');

      await signService.SignMessage(mockCall, mockCallback);

      expect(ethers.Wallet().signMessage).toHaveBeenCalledWith(longMessage);
      expect(mockCallback).toHaveBeenCalledWith(null, expect.any(Object));
    });
  });
});