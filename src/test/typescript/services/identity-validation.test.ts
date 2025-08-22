/**
 * Unit tests for Identity Registration Validation
 * Tests the critical security fixes for gist URL validation and identity spoofing prevention
 */

// Mock fetch globally
global.fetch = jest.fn();

// Mock ethers
jest.mock('ethers', () => ({
  ethers: {
    keccak256: jest.fn(),
    toUtf8Bytes: jest.fn(),
    verifyMessage: jest.fn(),
    Wallet: jest.fn().mockImplementation(() => ({
      address: '0x1234567890123456789012345678901234567890',
      signMessage: jest.fn().mockResolvedValue('0xmockedsignature')
    }))
  }
}));

// Mock EAS SDK
jest.mock('@ethereum-attestation-service/eas-sdk', () => ({
  EAS: jest.fn().mockImplementation(() => ({
    connect: jest.fn(),
    attest: jest.fn().mockResolvedValue({
      wait: jest.fn().mockResolvedValue({
        logs: [{ args: { uid: '0xmockedattestationuid' } }]
      })
    })
  })),
  SchemaEncoder: jest.fn().mockImplementation(() => ({
    encodeData: jest.fn().mockReturnValue('0xmockedencodeddata')
  }))
}));

// Mock SchemaConverter
jest.mock('../../../main/typescript/utils/SchemaConverter.js', () => {
  return jest.fn().mockImplementation(() => ({
    validateJsonData: jest.fn().mockReturnValue({ isValid: true }),
    createAttestationRequest: jest.fn().mockReturnValue({}),
    getSchemaUID: jest.fn().mockReturnValue('0x5908d03537f64f34dfd07fe11bb4d025f6ed66ec764dfe8909112fec9e548f9d'),
    easGraphqlToJson: jest.fn().mockReturnValue({
      domain: 'github.com',
      identifier: 'testuser'
    })
  }));
});

import { ContributionServiceImpl } from '../../../main/typescript/services/rest/ContributionServiceImpl.js';

describe('Identity Registration Validation', () => {
  let service: ContributionServiceImpl;
  const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

  beforeEach(() => {
    service = new ContributionServiceImpl();
    // Set up mock wallet
    (service as any).wallet = {
      address: '0x1234567890123456789012345678901234567890',
      signMessage: jest.fn().mockResolvedValue('0xmockedsignature')
    };
    mockFetch.mockClear();
  });

  describe('Gist URL Username Validation', () => {
    test('should accept valid gist URL with matching username', async () => {
      // Mock successful gist fetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValue(JSON.stringify({
          domain: 'github.com',
          identifier: 'validuser',
          ethereumAddress: '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
        }))
      } as any);

      const result = await service.validateGistContent(
        'https://gist.github.com/validuser/abc123',
        'validuser',
        '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
      );

      expect(result.valid).toBe(true);
    });

    test('should reject gist URL with mismatched username (SECURITY)', async () => {
      await expect(
        service.validateGistContent(
          'https://gist.github.com/allenday/abc123', // Different user
          'cyberstorm-daemon',                       // Claimed user
          '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
        )
      ).rejects.toThrow('Gist URL username mismatch. Expected gist from user "cyberstorm-daemon", but URL is from user "allendy"');
    });

    test('should reject invalid gist URL format', async () => {
      await expect(
        service.validateGistContent(
          'https://github.com/user/repo', // Not a gist URL
          'user',
          '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
        )
      ).rejects.toThrow('Invalid gist URL format');
    });
  });

  describe('Identity Registration', () => {
    test('should successfully register identity with valid data', async () => {
      // Mock successful gist validation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValue(JSON.stringify({
          domain: 'github.com',
          identifier: 'validuser',
          ethereumAddress: '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
        }))
      } as any);

      const result = await service.registerIdentity({
        body: {
          identifier: 'validuser',
          proofUrl: 'https://gist.github.com/validuser/abc123',
          ethereumAddress: '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
        }
      });

      expect(result.attestationUid).toBeDefined();
      expect(result.validationSignature).toBeDefined();
      expect(result.validator).toBeDefined();
      expect(result.attestationUid).not.toBe('undefined');
      expect(result.validationSignature).not.toBe('undefined');
    });

    test('should reject identity registration with mismatched gist username', async () => {
      await expect(
        service.registerIdentity({
          body: {
            identifier: 'cyberstorm-daemon',
            proofUrl: 'https://gist.github.com/allendy/abc123', // Wrong user
            ethereumAddress: '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
          }
        })
      ).rejects.toThrow('Gist URL username mismatch');
    });

    test('should reject identity registration with missing fields', async () => {
      await expect(
        service.registerIdentity({
          body: {
            identifier: 'user'
            // Missing proofUrl and ethereumAddress
          }
        })
      ).rejects.toThrow('proofUrl is required');
    });

    test('should reject identity registration with invalid field formats', async () => {
      await expect(
        service.registerIdentity({
          body: {
            identifier: '',
            proofUrl: 'not-a-gist-url',
            ethereumAddress: 'not-an-address'
          }
        })
      ).rejects.toThrow('identifier must be a non-empty string');
    });
  });

  describe('Return Value Validation', () => {
    test('should not return undefined values', async () => {
      // Mock successful gist validation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValue(JSON.stringify({
          domain: 'github.com',
          identifier: 'validuser',
          ethereumAddress: '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
        }))
      } as any);

      const result = await service.registerIdentity({
        body: {
          identifier: 'validuser',
          proofUrl: 'https://gist.github.com/validuser/abc123',
          ethereumAddress: '0xcc084F7A8d127C5F56C6293852609c9feE7b27eD'
        }
      });

      // Ensure no undefined values
      expect(result.attestationUid).not.toBeUndefined();
      expect(result.validationSignature).not.toBeUndefined();
      expect(result.validator).not.toBeUndefined();
      
      // Ensure values are not the string 'undefined'
      expect(result.attestationUid).not.toBe('undefined');
      expect(result.validationSignature).not.toBe('undefined');
      expect(result.validator).not.toBe('undefined');
    });
  });
});